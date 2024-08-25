import socket
import sys
import constants
import dns
import utils
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="the inital ip that will be scanned", type=str)
parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
parser.add_argument("-n", "--domainname", help="the initial domain name that will be scanned", type=str)
parser.add_argument("-dns", "--domainserver", help="the ip of the dns server, if the main ip is not a dns server", type=str)
args = parser.parse_args()

if len(args) > 3 or len(args) < 2:
    print("Usage: dnsexplore.py <IP> <FQDN> <OPTIONAL PORT>")
else:
    if args.domainname != None:
        domains: dns.DomainList = dns.DomainList()
        unscanneddomains: dns.DomainList = dns.DomainList()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            port: int = 53
            domainname: str = args.domainname
            if args.domainserver == None:
                ip: str = args.ip
            else:
                ip: str = args.domainserver
            addr: tuple[str, int] = (ip, port)
            unscanneddomains.AddDomain(dns.Domain(domainname))
            domains.AddDomain(dns.Domain(domainname))
            while len(unscanneddomains) > 0:
                fDNSmsg: bytes = dns.CreateHeader(dns.RequestType.TRANSFER) + dns.CreateQuestion(unscanneddomains)
                connection.sendto(fDNSmsg, addr)
                answer, _ = connection.recvfrom(1280)
                readableanswer: dns.DNSMessage = dns.InterpretDNSMessage(answer)
                if args.verbose:
                    for answer in readableanswer.answers:
                        if answer.type == constants.A:
                            domains.AddDomain(dns.Domain(answer.name, ip4=answer.rdata))
                            print(f"[*] FOUND: {answer.name}    Type: A    IP: {utils.GetIPv4(answer.rdata)}")
                        if answer.type == constants.AAAA:
                            domains.AddDomain(dns.Domain(answer.name, ip6=answer.rdata))
                            print(f"[*] FOUND: {answer.name}    Type: AAAA    IP: {utils.GetIPv6(answer.rdata)}")
            print("\n")
            print("Domains found:")
            for domain in domains:
                print(domain)