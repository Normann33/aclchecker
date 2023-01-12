#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import ipaddress
import getpass
from netmiko import ConnectHandler

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
green = bcolors.OKGREEN + bcolors.BOLD
red = bcolors.FAIL + bcolors.BOLD

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network


def find_acl(ip, x):
# Ищем интерфейс и access-list, x - это in или out
    count = 2
    while count > 0:
        output = ssh_connect.send_command(f"show ip route {ip}").split('\n')
        for i in output:
            if '*via' in i:
                nexthop = i.split()[1].strip(',')
                iface = i.split()[2].strip()
            elif 'via' in i and 'Known' not in i:
                iface = i.split()[-1]
            elif 'not in table' in i:
                output = ssh_connect.send_command("show ip route 0.0.0.0").split('\n')
            for i in output:
                 if ' *' in i:
                     nexthop = i.split()[1].strip(',')
        ip = nexthop
        count -=1
    print ('Interface: ' + iface)
    output = ssh_connect.send_command(f"show run int {iface}").split('\n')
    for i in output:
        if 'access-group' in i and x in i:
            acl = i.split()[-2]
            break
    else:
        acl = 'noacl'
        return acl
    print('Access-list: ' + acl)
    acl = ssh_connect.send_command(f"show access-l {acl}").split('\n') 
    return acl

def find_nexthop(ip):
    output = ssh_connect.send_command(f"show ip route {ip}").split('\n')
    for i in output:
        if 'not in table' in i:
            output = ssh_connect.send_command("show ip route 0.0.0.0").split('\n')
    for i in output:
        if ' *' in i:
            nexthop = i.split()[1].strip(',')
    print ('Next hop: ' + nexthop)
    return nexthop
 
def port_replace(port):
    ntl = ['bgp', 'chargen', 'cmd', 'daytime', 'discard', 'domain', 'drip', 'echo', 'exec', 'finger', 'ftp', 'ftp-data', 'gopher', 'hostname', 'ident', 'irc', 'klogin', 'kshell', 'login', 'lpd', 'nntp', 'pim-auto-rp', 'pop2', 'pop3', 'smtp', 'sunrpc', 'tacacs', 'talk', 'telnet', 'time', 'uucp', 'whois', 'www']
    ptl = [179, 19, 514, 13, 9, 53, 7, 512, 79, 21, 20, 70, 101, 113, 194, 543, 544, 513, 515, 119, 496, 109, 110, 25, 111, 514, 49, 517, 23, 37, 540, 43, 80]
    nul = ['biff', 'bootpc', 'bootps', 'discard', 'domain', 'echo', 'isakmp', 'mobile-ip', 'nameserver', 'netbios-dgm', 'netbios-ns', 'netbios-ss', 'non500-isakmp', 'ntp', 'pim-auto-rp', 'rip', 'snmp', 'snmptrap', 'sunrpc', 'syslog', 'tacacs', 'talk', 'tftp', 'time', 'who', 'xdmcp',]
    pul = [512, 68, 67, 9, 195, 53, 7, 500, 434, 42, 138, 137, 139, 4500, 123, 496, 520, 161, 162, 111, 514, 49, 517, 69, 37, 513, 177]
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

class line_split:
# Разбираем строку из аксесс-листа
    def acl_src(self, line):
        line = line.replace('any', '0.0.0.0 0.0.0.0').split()
        if line[3] == 'host':
            acl_src = net(line[4])
        else:
            acl_src = net(line[3] + '/' + line[4])
        return acl_src
    def acl_dst(self, line):
        line = line.replace('any', '0.0.0.0 0.0.0.0').split()
        if line[4] =='host':
            acl_dst = net(line[5])
        elif line[5] == 'host':
            acl_dst = net(line[6])
        else:
            acl_dst = net(line[5] + '/' + line[6])
        return acl_dst
    def check_port(self, line, port):
        line = line.split()
        port = int(port)
        if 'range' in line:
            r = line.index('range')
            x = int(line[r+1])
            y = int(line[r+2])
            if x <= port <= y:
                return True
        elif 'eq' in line:
            e = line.index('eq')
            x = int(port_replace(line[e+1]))
            if port == x:
                return True
            else:
                return False
        else:
            return False

def find_match(acl, x):
# Ищем совпадения в access-list-e, x - permit or deny
    for line in acl[1::]:
        try:
            if x in line and prot in line and src in l1.acl_src(line) and dst in l1.acl_dst(line) and (l1.check_port(line, dst_port) == True or ('eq' not in line and 'range' not in line)) and 'established' not in line:
                return line 
                break
            elif x in line and ' ip ' in line and src in l1.acl_src(line) and dst in l1.acl_dst(line):
                return line 
                break
        except ValueError:
            pass
    else:
        line = '99999 deny ip any any'
        return line
def compare():
    permit = find_match(acl, 'permit')
    deny = find_match(acl, 'deny')
    if int(permit.split()[0]) < int(deny.split()[0]):
        print(green + 'PASSED ' + bcolors.ENDC + permit)
    elif int(permit.split()[0]) > int(deny.split()[0]):
        print(red + 'BLOCKED ' + bcolors.ENDC + deny)
    else: 
        print (red + 'Blocked by implicit deny' + bcolors.ENDC)


try:
    prot = sys.argv[1] # Protocol
    src = addr(sys.argv[2]) # Source ip address
    dst = addr(sys.argv[3]) # Destination ip address
    dst_port = sys.argv[4] # Destination port
    device = sys.argv[5] # Router/Switch address
except:
    print ('Usage: protocol, source ip, destination ip, destination port, device ip')
    exit()
    

username = input('Username: ')
password = getpass.getpass('Password: ')

while True: 
    cisco_switch = {
        'device_type': 'cisco_ios',
        'ip': device,
        'username': username,
        'password': password,
        'secret':''
        }
    
    try:
        ssh_connect = ConnectHandler(**cisco_switch)
    except:
        print('Unable to connect to ' + device)
        exit()
    
    l1 = line_split()
    
    print ('Host: '+ str(ssh_connect.find_prompt())[:-1])
    
    print('IN:\n')
    try:
        acl = find_acl(src, 'in')
    except:
        print('Wrong source ip!')
        exit() 
    if acl == 'noacl':
        print('No access-list, ' + green + 'PASSED' + bcolors.ENDC)
    else:
        compare()
    print('\n')
    print('OUT:\n')
    try:
        acl = find_acl(dst, 'out')
    except:
        print('Wrong destination ip!')
        exit()
    if acl == 'noacl':
        print('No access-list, ' + green + 'PASSED' + bcolors.ENDC)
    else:
        compare()

    print('\n')
    device = find_nexthop(dst)

