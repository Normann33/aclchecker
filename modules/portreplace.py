def port_replace(port):
    ntl = ('bgp', 'chargen', 'cmd', 'daytime', 'discard', 'domain', 'echo', 'exec', 'finger', 'ftp', 'ftp-data', 'gopher', 'hostname', 'ident', 'irc', 'klogin', 'kshell', 'login', 'lpd', 'nntp', 'pim-auto-rp', 'pop2', 'pop3', 'smtp', 'sunrpc', 'syslog', 'tacacs', 'talk', 'telnet', 'time', 'uucp', 'whois', 'www')
    ptl = (179, 19, 514, 13, 9, 53, 7, 512, 79, 21, 20, 70, 101, 113, 194, 543, 544, 513, 515, 119, 496, 109, 110, 25, 111, 514, 49, 517, 23, 37, 540, 43, 80)
    nul = ('biff', 'bootpc', 'bootps', 'discard', 'dnsix', 'domain', 'echo', 'isakmp', 'mobile-ip', 'nameserver', 'netbios-dgm', 'netbios-ns', 'netbios-ss', 'non500-isakmp', 'ntp', 'pim-auto-rp', 'rip', 'snmp', 'snmptrap', 'sunrpc', 'syslog', 'tacacs', 'talk', 'tftp', 'time', 'who', 'xdmcp',)
    pul = (512, 68, 67, 9, 195, 53, 7, 500, 434, 42, 138, 137, 139, 4500, 123, 496, 520, 161, 162, 111, 514, 49, 517, 69, 37, 513, 177)
    if port in ntl:
        i = ntl.index(port)
        port = ptl[i]
        return port
    elif port in nul:
        i = nul.index(port)
        port = pul[i]
        return port
    else:
        return port
    
if __name__ == "__main__":
    port_replace(port)