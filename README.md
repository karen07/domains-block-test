# Domains block test
Domains-block-test sends fake TLS ClientHello to IPs from ips_file, SNI takes it from domains_file. If the response is that TLS is not correct, then the domain is not blocked, if there is no response a couple of times, that the domain is blocked.
## Usage
```sh
Commands:
  Required parameters:
    -domains_file /example.txt    Domains file path
    -ips_file /example.txt        IPs file path
```
