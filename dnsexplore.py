import socket
import sys
import random
from enum import Enum

# header constants
QUERY = 0*2**15
RESPONSE = 1*2**15
STDQUERY = 0*2**(15-4)
IQUERY = 1*2**(15-4)
STATUS = 2*2**(15-4)
AA = 2**(15-5)
TC = 2**(15-6)
RD = 2**(15-7)
RA = 2**(15-8)
NOERR = 0
FORMATERR = 1
SERVERFAIL = 2
NAMEERR = 3
NOTIMPL = 4
REFUSED = 5

# QTYPE constants
A = 1
NS = 2
MD = 3
MF = 4
CNAME = 5
SOA = 6
MB = 7
MG = 8
MR = 9
NULL = 10
WKS = 11
PRT = 12
HINFO = 13
MINFO = 14
MX = 15
TXT = 16
RP = 17
AFSDB = 18
X25 = 19
ISDN = 20
RT = 21
NSAP = 22
NSAP_PTR = 23
SIG = 24
KEY = 25
PX = 26
GPOS = 27
AAAA = 28
LOC = 29
NXT = 30
EID = 31
NIMLOC = 32
SRV = 33
ATMA = 34
NAPTR = 35
KX = 36
CERT = 37
A6 = 38
DNAME = 39
SINK = 40
OPT = 41
APL = 42
DS = 43
SSHFP = 44
IPSECKEY = 45
RRSIG = 46
NSEC = 47
DNSKEY = 48
DHCID = 49
NSEC3 = 50
TLSA = 52
SMIMEA = 53
HIP = 55
NINFO = 56
RKEY = 57
TALINK = 58
CDS = 59
CDNSKEY = 60
OPENPGPKEY = 61
CSYNC = 62
ZONEMD = 63
SVCD = 64
HTTPS = 65
SPF = 99
UINFO = 100
UID = 101
GID = 102
UNSPEC = 103
NID = 104
L32 = 105
L64 = 106
LP = 107
EUI48 = 108
EUI64 = 109
NXNAME = 128
TKEY = 249
TSIG = 250
IXFR = 251
AXFR = 252
MAILB = 253
MAILA = 254
ANY = 255
URI = 256
CAA = 257
AVC = 258
AVC = 258
DOA = 259
AMTRELAY = 260
RESINFO = 261
WALLET = 262
CLA = 263
IPN = 264
TA = 32768
DLC = 32769

# QCLASS constants
INTERNET = 1
CHAOS = 3
HESIOD = 4
NONE = 254
ANY = 255

class RequestType(Enum):
    STATUS = 0

class Header:
    def __init__(self, id: bytes, flags: bytes, rcode: bytes, qdcount: bytes, ancount: bytes, nscount: bytes, arcount: bytes):
        self.id: bytes = int.from_bytes(id, "big")
        self.flags: bytes = flags
        self.rcode: bytes = int.from_bytes(rcode, "big")
        self.qdcount: int = int.from_bytes(qdcount, "big")
        self.ancount: int = int.from_bytes(ancount, "big")
        self.nscount: int = int.from_bytes(nscount, "big")
        self.arcount: int = int.from_bytes(arcount, "big")

class Question:
    def __init__(self, qname: str, qtype: bytes, qclass: bytes):
        self.qname: str = qname
        self.qtype: int = int.from_bytes(qtype, "big")
        self.qclass: int = int.from_bytes(qclass, "big")

class ResourceRecord:
    def __init__(self, name: str, type: bytes, _class: bytes, ttl: bytes, rdata: bytes):
        self.name: str = name
        self.type: int = int.from_bytes(type, "big")
        self._class: int = int.from_bytes(_class, "big")
        self.ttl: int = int.from_bytes(ttl, "big")
        self.rdata: bytes = rdata

class DNSMessage:
    def __init__(self, header: Header, questions: list[Question], answers: list[ResourceRecord], authority: list[ResourceRecord], additional: list[ResourceRecord]):
        self.header: Header = header
        self.questions: list[Question] = questions
        self.answers: list[ResourceRecord] = answers
        self.authority: list[ResourceRecord] = authority
        self.additional: list[ResourceRecord] = additional

class Domain:
    def __init__(self, name: str, ip4: bytes = None, ip6: bytes = None):
        self.name: str = name
        self.ip4: bytes = ip4
        self.ip6: bytes = ip6
    def __str__(self):
        return f"Name: {self.name}, IPv4: {GetIPv4(self.ip4)}, IPv6: {GetIPv6(self.ip6)}"

class DomainList:
    def __init__(self):
        self.domains: list[Domain] = []
    def AddDomain(self, domain: Domain):
        isin = False
        for index, currdomain in enumerate(self.domains):
            if currdomain.name == domain.name:
                if domain.ip4 != None:
                    self.domains[index].ip4 = domain.ip4
                if domain.ip6 != None:
                    self.domains[index].ip6 = domain.ip6
                isin = True
        if not isin:
            self.domains.append(domain)
    def __iter__(self):
        self.index = 0
        return self
    def __next__(self):
        if self.index == len(self.domains):
            raise StopIteration
        self.index += 1
        return self.domains[self.index-1]
            


type requesttype = RequestType

def CreateHeader(type: requesttype) -> bytes:
    if type == RequestType.STATUS:
        IDi: int = random.randint(0, 2**15)
        IDb: bytes = IDi.to_bytes(2, "big")
        flagsi: int = QUERY + RD
        flagsb: bytes = flagsi.to_bytes(2, "big")
        QDcounti: int = 1
        QDcountb: bytes = QDcounti.to_bytes(2, "big")
        ANcounti: int = 0
        ANcountb: bytes = ANcounti.to_bytes(2, "big")
        NScounti: int = 0
        NScountb: bytes = NScounti.to_bytes(2, "big")
        ARcounti: int = 0
        ARcountb: bytes = ARcounti.to_bytes(2, "big")
        return IDb + flagsb + QDcountb + ANcountb + NScountb + ARcountb

def CreateQuestion(domain: str) -> bytes:
    labels: list[str] = domain.split(".")
    question: bytes = b""
    for label in labels:
        binarylabel: bytes = len(label).to_bytes(1, "big")
        binarylabel += label.encode("ascii")
        question += binarylabel
    question += b"\x00"
    question += ANY.to_bytes(2, "big")
    question += INTERNET.to_bytes(2, "big")
    return question

def GetHeader(message: bytes) -> tuple[Header, bytes]:
    id: bytes = message[:2]
    flags: bytes = message[2:3]
    rcode: bytes = message[3:4]
    qdcount: bytes = message[4:6]
    ancount: bytes = message[6:8]
    nscount: bytes = message[8:10]
    arcount: bytes = message[10:12]
    return (Header(id, flags, rcode, qdcount, ancount, nscount, arcount), message[12:])

def GetLabel(message: bytes) -> tuple[str, bytes]:
    index: int = 0
    label: str = ""
    while message[index] != 0:
        length: int = message[index]
        index += 1
        label += message[index:index+length].decode("ascii") + "."
        index += length
    index += 1
    return (label, message[index:])

def GetQuestion(message: bytes, fullmessage: bytes) -> tuple[Question, bytes]:
    if message[0] - 192 >= 0:
        offset: int = int.from_bytes(message[0:2], "big") - 49152
        label, _ = GetLabel(fullmessage[offset:])
        message = message[2:]
    else:
        label, message = GetLabel(message)
    qtype: bytes = message[0:2]
    qclass: bytes = message[2:4]
    if len(message) > 4:
        return (Question(label, qtype, qclass), message[4:])
    else:
        return (Question(label, qtype, qclass), None)

def GetResource(message: bytes, fullmessage: bytes) -> tuple[ResourceRecord, bytes]:
    if message[0] - 192 >= 0:
        offset: int = int.from_bytes(message[0:2], "big") - 49152
        label, _ = GetLabel(fullmessage[offset:])
        message = message[2:]
    else:
        label, message = GetLabel(message)
    type: bytes = message[0:2]
    _class: bytes = message[2:4]
    ttl: bytes = message[4:8]
    rdlength: int = int.from_bytes(message[8:10], "big")
    rdata: bytes = message[10:10+rdlength]
    if len(message) > 10+rdlength:
        return (ResourceRecord(label, type, _class, ttl, rdata), message[10+rdlength:])
    else:
        return (ResourceRecord(label, type, _class, ttl, rdata), None)


def InterpretDNSMessage(message: bytes) -> DNSMessage:
    fullmessage: bytes = message
    header, message = GetHeader(message)
    questions: list[Question] = []
    for _ in range(header.qdcount):
        question, message = GetQuestion(message, fullmessage)
        questions.append(question)
    answers: list[ResourceRecord] = []
    for _ in range(header.ancount):
        answer, message = GetResource(message, fullmessage)
        answers.append(answer)
    authoritys: list[ResourceRecord] = []
    for _ in range(header.nscount):
        authority, message = GetResource(message, fullmessage)
        authoritys.append(authority)
    additionals: list[ResourceRecord] = []
    for _ in range(header.arcount):
        additional, message = GetResource(message, fullmessage)
        additionals.append(additional)
    return DNSMessage(header, questions, answers, authoritys, additionals)
    
def GetIPv4(ip: bytes) -> str:
    iplist: list[str] = []
    for i in range(0, 8, 2):
        iplist.append(str(int.from_bytes(ip[i:i+2], "big")))
    return ".".join(iplist)

def GetIPv6(ip: bytes) -> str:
    iplist: list[str] = []
    for i in range(0, 16, 2):
        octet = int.from_bytes(ip[i:i+2], "big")
        if octet == 0:
            iplist.append("")
        else:
            iplist.append(format(octet, "x"))
    index = 0
    previous = ""
    while index < len(iplist):
        if iplist[index] == previous and previous == "":
            iplist.pop(index)
        else:
            previous = iplist[index]
            index += 1
    return ":".join(iplist)


args: list[str] = sys.argv[1:]
domains: DomainList = DomainList()

if len(args) > 3 or len(args) < 2:
    print("Usage: dnsexplore.py <IP> <FQDN> <OPTIONAL PORT>")
else:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        port: int = 53
        fqdn: str = args[1]
        if len(args) == 3:
            port = int(args[2])
        ip: str = args[0]
        addr: tuple[str, int] = (ip, port)
        fDNSmsg: bytes = CreateHeader(RequestType.STATUS) + CreateQuestion(fqdn)
        connection.sendto(fDNSmsg, addr)
        answer, _ = connection.recvfrom(1280)
        readableanswer: DNSMessage = InterpretDNSMessage(answer)
        for answer in readableanswer.answers:
            if answer.type == A:
                domains.AddDomain(Domain(answer.name, ip4=answer.rdata))
                print(f"Name: {answer.name}    Type: A    IP: {GetIPv4(answer.rdata)}")
            if answer.type == AAAA:
                domains.AddDomain(Domain(answer.name, ip6=answer.rdata))
                print(f"Name: {answer.name}    Type: AAAA    IP: {GetIPv6(answer.rdata)}")
        print("\n")
        print("Domains found:")
        for domain in domains:
            print(domain)