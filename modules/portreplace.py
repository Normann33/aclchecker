def port_replace(port):

    tcpDict = {'bgp': 179, 'chargen': 19, 'cmd': 514, 'daytime': 13, 'discard': 9, 'domain': 53, 'echo': 7, 'exec': 512, 'finger': 79, 'ftp': 21, 'ftp-data': 20, 'gopher': 70, 'hostname': 101, 'ident': 113, 'irc': 194, 'klogin': 543, 'kshell': 544, 'login': 513, 'lpd': 515, 'nntp': 119, 'pim-auto-rp': 496, 'pop2': 109, 'pop3': 110, 'smtp': 25, 'sunrpc': 111, 'syslog': 514, 'tacacs': 49, 'talk': 517, 'telnet': 23, 'time': 37, 'uucp': 540, 'whois': 43, 'www': 80}

    udpDict = {'biff': 512, 'bootpc': 68, 'bootps': 67, 'discard': 9, 'dnsix': 195, 'domain': 53, 'echo': 7, 'isakmp': 500, 'mobile-ip': 434, 'nameserver': 42, 'netbios-dgm': 138, 'netbios-ns': 137, 'netbios-ss': 139, 'non500-isakmp': 4500, 'ntp': 123, 'pim-auto-rp': 496, 'rip': 520, 'snmp': 161, 'snmptrap': 162, 'sunrpc': 111, 'syslog': 514, 'tacacs': 49, 'talk': 517, 'tftp': 69, 'time': 37, 'who': 513, 'xdmcp': 177}

    if port in tcpDict:
        return tcpDict[port]
    elif port in udpDict:
        return udpDict[port]
    else:
        return port
    
if __name__ == '__main__':
    print(port_replace(port))