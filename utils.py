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