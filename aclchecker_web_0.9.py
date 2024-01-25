#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# from datetime import datetime
import re
from netmiko import ConnectHandler
from modules.findmgmt import findmgmt
import ipaddress
import traceback
import argparse
from modules.normalise import normalise
from modules.compare import compare

# startTime = datetime.now()

green = '<i style="color:green;font-size:12px;font-family:monospace;">'
red = '<i style="color:red;font-size:12px;font-family:monospace;">'

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network

parser = argparse.ArgumentParser(
                    prog='AclChecker',
                    description='Checks if packet with given parameters will pass access-lists on all hops',
                    epilog='Example: aclchecker.py -r tcp -s 192.168.1.10 -d 172.16.10.5 -p 443 -g ag-of-1')

parser.add_argument('-r', '--prot', help='Protocol [tcp|udp|ip|icmp], etc', required=True)
parser.add_argument('-s', '--src', help='Source ip address', required=True)
parser.add_argument('-d', '--dst', help='Destination ip address', required=True)
parser.add_argument('-p', '--dport', help='Destination port', required=True)
parser.add_argument('-g', '--gw', help='Gateway (where to start from)', required=True)
parser.add_argument('-v', '--vrf', help='VRF on first hop (optional)')

class Version:

    @staticmethod
    def detectVersion():
        vtext = ssh_connect.send_command('show version').split('\n')[0]
        if 'NX-OS' in vtext:
            return Nexus(Device)
        elif 'Arista' in vtext:
            return Arista(Device)
        else:
            return Device()

class Vrf():

    def __init__(self, p2pIface='None'):
        self.p2pIface = p2pIface

    def detectVrf(self):
        output = ssh_connect.send_command(f"show run interface {self.p2pIface}")
        rawvrf = re.findall('vrf (member|forwarding) (\S+|\s+)', output)
        if rawvrf:
            vrf = rawvrf[0][1]
        else:
            vrf = 'default'
        return vrf

class Device():
    def __init__(self, *args) -> None:
        self.isDirectlyConnected = False

    def detectNextHop(self, ip, vrf):
        if vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {ip}")
        else:
            output = ssh_connect.send_command(f"show ip route  vrf {vrf} {ip}")
        addrRaw = (re.findall("((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected)", output))
        for i in addrRaw:
            if 'directly connected' in i or 'attached' in i:
                addrRaw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output))
                nexthop = addrRaw[0]
                self.isDirectlyConnected = True
                return nexthop, self.isDirectlyConnected
            elif 'not in table' in i and vrf == 'default':
                output = ssh_connect.send_command('show ip route 0.0.0.0')
                break
            elif 'not in table' in i and vrf != 'default':
                output = ssh_connect.send_command(f'show ip route  vrf {vrf} 0.0.0.0')
        addrRaw = (re.findall("((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table)", output))
        if 'not in table' in addrRaw:
            print ('No further route')
            exit()
        else:
            nexthop = addrRaw[0].split()[1]
        # print ('    Next hop:  <span class="ip">' + nexthop + '</span>')
        return nexthop, self.isDirectlyConnected

    def detectIface(self, nexthop, vrf):
        iface = ''
        if vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {nexthop}")
        else:
            output = ssh_connect.send_command(f"show ip route  vrf {vrf} {nexthop}")
        rawiface = re.findall('(\* directly connected, via) (\S+|\s+)', output)
        iface = rawiface[0][-1]
        return iface
    
    def detectP2pIface(self, ip):
        output = ssh_connect.send_command(f"show ip interface brief | inc {ip}").split(' ')
        p2pIface = output[0]
        return p2pIface

    def detectAcl(self, iface, x):
        #x - in or out
        output = ssh_connect.send_command(f"show run int {iface}")
        rawacl = re.findall(f'(ip access-group) (\S+|\s+) {x}', output)
        if rawacl:
            aclname = rawacl[0][-1]
            acl = ssh_connect.send_command(f"show access-l {aclname}").strip().split('\n')
            if 'Extended IP access list' in acl[0]:
                acl.pop(0)
            acl = normalise(acl, ssh_connect)
            return aclname, acl
        else:
            acl = aclname = 'noacl'
        # print('    Access-list: <span class="title">' + acl + '</span>')
        return aclname, acl
    
    def __str__(self):
        return 'IOS device'

class Arista (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip=ip
    def __str__(self):
        print ('This is Arista, baby. Manual analysis only')
        exit()

class Nexus (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def __str__(self):
        return 'Nexus device'
    def detectIface(self, nexthop, vrf):
        if vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {nexthop}")
        else:
            output = ssh_connect.send_command(f"show ip route  vrf {vrf} {nexthop}")
        rawiface = re.findall('(\*via) (\S+|\s+)', output)
        iface = rawiface[0][-1]
        return iface
    def detectP2pIface(self, ip):
        output = ssh_connect.send_command(f"show ip interface brief vrf all | inc {ip}").split(' ')
        p2pIface = output[0]
        return p2pIface
    
username = 'your_user'
password = 'your_password'

args = parser.parse_args()

device = args.gw
src = addr(args.src.strip())
dst = addr(args.dst.strip())
dst_port = args.dport.strip()
prot = args.prot.strip()

if args.vrf:
    firstHopVrf = args.vrf
else:
    firstHopVrf = 'default'


isFirstHop = True
p2pIface = ''
vrf = firstHopVrf

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
        print('Unable to connect to ', device)
        exit()

    print ('<div class="host">' + str(ssh_connect.find_prompt())[:-1] + '</div>')
    print('<div class="container">')
    print('<span class="title">IN:</span>')

    d = Version.detectVersion()
    if isFirstHop == False:
        p2pIface = d.detectP2pIface(dstnexthop)
        v = Vrf(p2pIface)
        vrf = v.detectVrf()
    print('<span class="title">    VRF: </span>', vrf)
    nexthop, idc = d.detectNextHop(src, vrf)
    srciface = d.detectIface(nexthop, vrf)
    print('    Interface: <span class="title">' + srciface+ '</span>')
    try:
        aclname, acl = d.detectAcl(srciface, 'in')
    except Exception:
        print(red + 'Wrong source ip!' + '</i>')
        traceback.print_exc()
        exit() 
    if acl == 'noacl':
        print('<span class ="passed">    PASSED</span>, No access-list')
    else:
        print('    Access-list: <span class="title">', aclname, '</span>')
        compare(acl, src, dst, dst_port, prot)
    print('<span class="title">OUT:</span>')
    d.isDirectlyConnected = False
    dstnexthop, dstidc = d.detectNextHop(dst, vrf)
    dstiface = d.detectIface(dstnexthop, vrf)
    print('    Interface: <span class="title">' + dstiface + '</span>')
    try:
        aclname, acl = d.detectAcl(dstiface, 'out')
    except Exception:
        print('Wrong destination ip!')
        exit()
    if acl == 'noacl':
        print('<span class ="passed">    PASSED</span>, No access-list')
    else:
        print('    Access-list: <span class="title">',  aclname, '</span>')
        compare(acl, src, dst, dst_port, prot)
    print ('Next hop:  <span class="ip">' + dstnexthop + '</span>')
    if dstidc == True:
        print ('Next hop is directly connected, exiting')
        exit()
    device = findmgmt(dstnexthop)
    isFirstHop = False
    v = Vrf(p2pIface)
    print('</div>')
    # print(datetime.now() - startTime)