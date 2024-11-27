#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# from datetime import datetime
import re
from netmiko import ConnectHandler
from cryptography.fernet import Fernet
from modules.config import SECRET_KEY, ENABLE_KEY
from modules.findmgmt import findmgmt
import ipaddress
import traceback
import argparse
from modules.normalise import normalise
from modules.compare import compare
from modules.asa import Asa
import time

# startTime = datetime.now()

cipher_suite = Fernet(SECRET_KEY)

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network


class Version:

    @staticmethod
    def detectVersion():
        vtext = ssh_connect.send_command('show version').split('\n')[:2]
        vtext = ''.join(vtext)
        if 'NX-OS' in vtext:
            return Nexus(Device)
        elif 'Arista' in vtext:
            return Arista(Device)
        elif 'Adaptive Security Appliance' in vtext:
            return Asa(ssh_connect, host_ip)
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

    def getAddrRaw(self, output):
        self.addrRaw = (re.findall("((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)", output))
        return self.addrRaw

    def getNexthop(self, addrRaw):
        nexthop = addrRaw[0].split()[1]
        return nexthop

    def showVrf(self, ip, vrf):
        self.output = ssh_connect.send_command(f"show ip route vrf {vrf} {ip}")
        return self.output

    def detectNextHop(self, ip, vrf):
        self.vrf = vrf
        if vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {ip}")
        else:
            output = self.showVrf(ip, self.vrf)
        addrRaw = self.getAddrRaw(output)
        for i in addrRaw:
            if 'Null' in i:
                nexthop = None
                return nexthop, self.isDirectlyConnected
            if 'directly connected' in i or 'attached' in i:
                addrRaw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output))
                nexthop = addrRaw[0]
                self.isDirectlyConnected = True
                return nexthop, self.isDirectlyConnected
            elif 'not in table' in i and vrf == 'default':
                output = ssh_connect.send_command('show ip route 0.0.0.0')
                break
            elif 'not in table' in i and vrf != 'default':
                output = ssh_connect.send_command(f'show ip route  vrf {self.vrf} 0.0.0.0')
        addrRaw = self.getAddrRaw(output)
        if 'not in table' in addrRaw:
            nexthop = None
            return nexthop, self.isDirectlyConnected
        else:
            nexthop = self.getNexthop(addrRaw)
            print (addrRaw, nexthop)
        return nexthop, self.isDirectlyConnected

    def rawIface(self, output):
        rawiface = re.findall('(directly connected, via) (\S+|\s+)', output)
        return rawiface

    def detectIface(self, nexthop, vrf):
        iface = ''
        if vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {nexthop}")
        else:
            output = ssh_connect.send_command(f"show ip route  vrf {vrf} {nexthop}")
        rawiface = self.rawIface(output)
        iface = rawiface[0][-1].strip(',')
        return iface
    
    def detectP2pIface(self, ip):
        output = ssh_connect.send_command(f"show ip interface brief | inc {ip}").split(' ')
        p2pIface = output[0]
        return p2pIface

    def aclCommand(self, aclname):
        acl = ssh_connect.send_command(f"show access-l {aclname}").strip().split('\n')
        return acl

    def detectAcl(self, iface, x):
        #x - in or out
        output = ssh_connect.send_command(f"show run int {iface}")
        rawacl = re.findall(f'(ip access-group) (\S+|\s+) {x}', output)
        if rawacl:
            aclname = rawacl[0][-1]
            acl = self.aclCommand(aclname)
            if 'Extended IP access list' in acl[0]:
                acl.pop(0)
            acl = normalise(acl, ssh_connect)
            return aclname, acl
        else:
            acl = aclname = 'noacl'
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

    def rawIface(self, output):
        rawiface = re.findall('(directly connected,) (\S+|\s+)', output)
        return rawiface

    def getAddrRaw(self, output):
        self.addrRaw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)", output))
        return self.addrRaw

    def getNexthop(self, addrRaw):
        nexthop = addrRaw[1]
        return nexthop

    def aclCommand(self, aclname):
        acl = ssh_connect.send_command(f"show ip access-l {aclname}").strip().split('\n')
        return acl


class Nexus (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def __str__(self):
        return 'Nexus device'
    
    def showVrf(self, ip, vrf):
        self.output = ssh_connect.send_command(f"show ip route {ip} vrf {vrf}")
        return self.output

    def detectIface(self, nexthop, vrf):
        self.vrf = vrf
        if self.vrf == 'default':
            output = ssh_connect.send_command(f"show ip route {nexthop}")
        else:
            output = ssh_connect.send_command(f"show ip route {nexthop} vrf {self.vrf}")
        rawiface = re.findall('(\*via) (\S+|\s+) (\S+|\s+)', output)
        iface = rawiface[0][-1].strip(',')
        return iface
    
    def detectP2pIface(self, ip):
        output = ssh_connect.send_command(f"show ip interface brief vrf all | inc {ip}").split(' ')
        p2pIface = output[0]
        return p2pIface
    
# username = ''
# password = ''




firstHopVrf = 'default'

p2pIface = ''
vrf = firstHopVrf

host_ip = '' # Parameter for Cisco ASA


def findHostName():
    isEnabled = True
    command = ssh_connect.find_prompt()
    if '>' in command:
        isEnabled = False
    hostname = str(ssh_connect.find_prompt())[:-1]
    return isEnabled, hostname

def run(username, password, prot, src, dst, dst_port, gw, vrf):
    isFirstHop = True
    global ssh_connect, device, results, host_ip
    host_ip = src
    results = []
    device = gw
    resultIndex = 0
    enable = cipher_suite.decrypt(ENABLE_KEY).decode()

    while True:
        cisco_switch = {
            'device_type': 'cisco_ios',
            'ip': device,
            'username': username,
            'password': password,
            'secret': enable,
            }
        if 'asa' in device:
            cisco_switch['device_type'] = 'cisco_asa'
        try:
            ssh_connect = ConnectHandler(**cisco_switch)
        except:
            yield {'index': resultIndex,'hostname': device}
            yield {'index': resultIndex, 'endmessage': f'Cant connect to {device}'}
            results.append({'endmessage': f'Cant connect to {device}'})
            return results
        
        # First of all we adding current hostname to results
        isEnabled, hostname = findHostName()
        yield {'index': resultIndex,'hostname': hostname}

        if isEnabled == False:
            ssh_connect.enable()
            print(str(ssh_connect.find_prompt()))
        
        # Detect version of network device
        d = Version.detectVersion()

        global p2pIface, idc, dstidc
        
        # If device is not first hop, we detect p2p interface and vrf
        if isFirstHop == False:
            print('DEBUG if first hop == False, p2pIface = d.detectP2pIfase')
            p2pIface = d.detectP2pIface(dstnexthop)
            v = Vrf(p2pIface)
            vrf = v.detectVrf()
        yield {'index': resultIndex,'vrf': vrf}

        # Detect source interface
        nexthop, idc = d.detectNextHop(src, vrf)
        print('Nexthop after detection', nexthop)
        if nexthop == None:
            addToResults('endmessage', 'No further route in this VRF', resultIndex)
            return results
        srciface = d.detectIface(nexthop, vrf)
        yield {'index': resultIndex, 'srciface': srciface}

        # Detect access-list on source interface
        try:
            aclname, acl = d.detectAcl(srciface, 'in')
            yield {'index': resultIndex, 'srcaclname': aclname}
        except Exception:
            print(red + 'Wrong source ip!' + '</i>')
            traceback.print_exc()
            exit() 

        # Check if we can pass access-list
        if acl == 'noacl':
            yield {'index': resultIndex, 'srcresult': 'PASSED, no access-list'}
        else:
            yield {'index': resultIndex, 'srcresult': compare(acl, src, dst, dst_port, prot)}

        # Detect outgoing interface and next hop
        d.isDirectlyConnected = False
        print('DEBUG dstnexthop, dstidc ', d.detectNextHop(dst, vrf))
        dstnexthop, dstidc = d.detectNextHop(dst, vrf)
        if dstnexthop == None:
            yield {'index': resultIndex, 'endmessage': 'No further route in this VRF'}
        dstiface = d.detectIface(dstnexthop, vrf)
        yield {'index': resultIndex, 'dstiface': dstiface}

        # Detect access-list on destination interface
        try:
            aclname, acl = d.detectAcl(dstiface, 'out')
            yield {'index': resultIndex, 'dstaclname': aclname}
        except Exception:
            print('Wrong destination ip!')
            exit()

        # Check if we can pass access-list
        if acl == 'noacl':
            yield {'index': resultIndex, 'dstresult': 'PASSED, no access-list'}
        else:
            yield {'index': resultIndex, 'dstresult': compare(acl, src, dst, dst_port, prot)}
        
        # If destination is directly connected - finish
        if dstidc == True:
            print ('Target is directly connected, exiting')
            yield {'index': resultIndex, 'endmessage': 'Target is directly connected'}
            resultIndex += 1
            print(results)
            return results
        
        # Detect management ip of next hop
        device = findmgmt(dstnexthop)
        yield {'index': resultIndex, 'nexthop': device}
        isFirstHop = False
        v = Vrf(p2pIface)
        print('</div>')
        resultIndex += 1
    else:
        addToResults('endmessage', 'DONE', resultIndex)
        return results




if __name__ == "__main__":
    results = run(username, password, prot, addr(src), addr(dst), dst_port, gw, vrf)
    print(results)