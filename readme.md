# DNSexplore

## What is DNSexplore's purpose

DNSexplore is made to enumerate all subdomains and ip adresses that can be obtained from a single domain and ip using domain tranfers, every subdomain and ip found will also be scanned, after finishing all ips and domains (with their ips) will be returned

I also plan on adding brute force subdomain enumeration to increase the possibility of finding new subdomains and ips

I also plan on adding certificate enumeration, so if the domain has a certificate then the program looks for the said certificate

## How to use DNSexplore

```bash
python3 dnsexplore.py <IP> <FQDN> <OPTIONAL PORT>
```