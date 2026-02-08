# Domains block test
Domains-block-test sends a synthetic TLS ClientHello to IP addresses listed in an input file, using SNI values taken from a domains file. If the server responds with a TLS error, the domain is considered unblocked. If no response is received after several attempts, the domain is considered blocked.
## Usage
```sh
Commands:
  Required parameters:
    -d  "/test.txt"  Domains file path
    -i  "/test.txt"  IPs file path
    -n  "test"       Dev name
    -r  "xxx"        Request per second
```
