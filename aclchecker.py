#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Version 0.7

import os
import re
import sys
import ipaddress
import getpass
from netmiko import ConnectHandler
import traceback

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

def objGroupReplace (line, name, item):
    '''Функция заменяет имя object-group в строке на ip-адреса'''
    lineList = line.split()
    for i in lineList:
        if i == name:
            lineList[lineList.index(i)] = item
            line = ' '.join(lineList)
            return line

def hostReplace(line):
    lineList = line.split()
    indices = [i for i, x in enumerate(lineList) if x == "255.255.255.255"]
    for i in range(len(indices)):
        r = indices[i]
        x = r+1
        lineList[r] = lineList[x]
        lineList[x] = '255.255.255.255'
    line = ' '.join(lineList)
    return line

def normalise(acl):
    '''Приведение ip адресов в строках к единому виду'''
    acl_clean = []
    for line in acl:
        line = line.replace('host ', '255.255.255.255 ').replace('any', '0.0.0.0 0.0.0.0')
        if "255.255.255.255" in line:
            line = hostReplace(line)
        lineList = line.split()
        if "object-group" in line:
            objGroupFinder = re.finditer(r'object-group (\S+)', line)
            objGroupNames = []
            for i in objGroupFinder:
                objGroupNames.append(i.group(1))
            objGroups = {}
            for i in objGroupNames:
                objgroupItemsRaw = ssh_connect.send_command(f"show object-group name {i}").replace("host", "255.255.255.255")
                objgroupItemsRaw = hostReplace(objgroupItemsRaw)
                objgroupItemsRaw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", objgroupItemsRaw))
                objgroupItems = []
                x = 0
                for j in range(int(len(objgroupItemsRaw)/2)):
                    objgroupItems.append(' '.join(objgroupItemsRaw[x:x+2]))
                    x += 2
                objGroups[i] = objgroupItems
            #print(objGroups)
            tempAcl = []
            if len(objGroupNames) == 1:
                for item in objgroupItems:
                    acl_clean.append(objGroupReplace(line, objGroupNames[0], item).replace("object-group", ""))
            else:
                for item in objgroupItems:
                    tempAcl.append(objGroupReplace(line, objGroupNames[0], item))
                for i in tempAcl:
                    for item in objgroupItems:
                        acl_clean.append(objGroupReplace(i, objGroupNames[1], item).replace("object-group", ""))
        else:
            acl_clean.append(line.strip('\n'))
    return acl_clean

def find_vrf(iface):
    output = ssh_connect.send_command(f"show run int {iface}").split('\n')
    for i in output:
        if "vrf member" in i:
            vrf = i.split()[-1]
        else:
            vrf = 'default'
    return vrf

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
    acl = normalise(acl)
    return acl[1::]

def find_nexthop(ip):
#    if vrf == 'default':
    output = ssh_connect.send_command(f"show ip route {ip}").split('\n')
#    else:
#        output = ssh_connect.send_command(f'show ip route {ip} vrf {vrf}').split('\n')
    for i in output:
        if 'not in table' in i:
            output = ssh_connect.send_command("show ip route 0.0.0.0").split('\n')
    for i in output:
        if ' *' in i:
            nexthop = i.split()[1].strip(',')
    print ('Next hop: ' + nexthop)
    return nexthop
 
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

class line_split:
# Разбираем строку из аксесс-листа
    def acl_addr(self, line):
        acl_src = ''
        acl_dst = ''
        port_line = ''
        if "Extended IP access list" in line:
            pass
        else:
            ip_addresses = re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        try:
            z = line.split().index(ip_addresses[3])
        except Exception:
            print ('DEBUG Не могу разобрать строку', line)
            pass
        port_line = line.split()[z::]
        try:
            acl_src = net(ip_addresses[0] + '/' + ip_addresses[1])
            acl_dst = net(ip_addresses[2] + '/' + ip_addresses[3])
        except:
            # print("DEBUG acl_addr: Не могу разобрать строку", line)
            pass 
        return acl_src, acl_dst, port_line
    def check_port(self, line, port):
        # port = int(port)
        if 'range' in line:
            r = line.index('range')
            x = int(line[r+1])
            y = int(line[r+2])
            if x <= int(port) <= y:
                return True
        elif 'eq' in line:
            for item in line:
                if item.isalpha():
                    item = port_replace(item)
                if port == str(item):
                    return True
            else:
                return False
        else:
            return False

def find_match(acl, x):
# Ищем совпадения в access-list-e, x - permit or deny
    for line in acl:
        acl_src, acl_dst, port_line = l1.acl_addr(line)
        try:
            if x in line and prot in line and src in acl_src and dst in acl_dst and 'established' not in line and (l1.check_port(port_line, dst_port) == True or ('eq' not in port_line and 'range' not in port_line)) and 'established' not in line:
                return line 
                break
            elif x in line and ' ip ' in line and src in acl_src and dst in acl_dst:
                return line 
                break
        except Exception:
        #    traceback.print_exc()
            print('DEBUG: find_match Не могу разобрать строку ', line)
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

#username = os.environ.get("CISCOUSER", '')
#password = os.environ.get("CISCOPASS", '')


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
    except Exception:
        print('Wrong source ip!')
        traceback.print_exc()
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

