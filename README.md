# Domains block test
Domains-block-test sends fake TLS ClientHello to IPs from ip file, SNI takes it from domains file. If the response is that TLS is not correct, then the domain is not blocked, if there is no response a couple of times, that the domain is blocked.
## Usage
```sh
Commands:
  Required parameters:
    -d  "/test.txt"  Domains file path
    -i  "/test.txt"  IPs file path
    -n  "test"       Dev name
    -r  "xxx"        Request per second
```
