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
    def detect_version():
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

    def __init__(self, p2p_iface='None'):
        self.p2p_iface = p2p_iface

    def detect_vrf(self):
        output = ssh_connect.send_command(f"show run interface {self.p2p_iface}")
        rawvrf = re.findall('vrf (member|forwarding) (\S+|\s+)', output)
        if rawvrf:
            vrf = rawvrf[0][1]
        else:
            vrf = 'default'
        return vrf

class Device():
    def __init__(self, *args) -> None:
        self.is_directly_connected = False

    def get_addr_raw(self, output):
        self.addr_raw = (re.findall('((?:\* |\*via )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)', output))
        return self.addr_raw

    def get_nexthop(self, addr_raw):
        nexthop = addr_raw[0].split()[1]
        return nexthop

    def show_vrf(self, ip, vrf):
        self.output = ssh_connect.send_command(f'show ip route vrf {vrf} {ip}')
        return self.output

    def detect_next_hop(self, ip, vrf):
        self.vrf = vrf
        if vrf == 'default':
            output = ssh_connect.send_command(f'show ip route {ip}')
        else:
            output = self.show_vrf(ip, self.vrf)
        addr_raw = self.get_addr_raw(output)
        for i in addr_raw:
            if 'Null' in i:
                nexthop = None
                return nexthop, self.is_directly_connected
            if 'directly connected' in i or 'attached' in i:
                addr_raw = (re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output))
                nexthop = addr_raw[0]
                self.is_directly_connected = True
                return nexthop, self.is_directly_connected
            elif 'not in table' in i and vrf == 'default':
                output = ssh_connect.send_command('show ip route 0.0.0.0')
                break
            elif 'not in table' in i and vrf != 'default':
                output = ssh_connect.send_command(f'show ip route  vrf {self.vrf} 0.0.0.0')
        addr_raw = self.get_addr_raw(output)
        if 'not in table' in addr_raw:
            nexthop = None
            return nexthop, self.is_directly_connected
        else:
            nexthop = self.get_nexthop(addr_raw)
            print (addr_raw, nexthop)
        return nexthop, self.is_directly_connected

    def raw_iface(self, output):
        raw_iface = re.findall('(directly connected, via) (\S+|\s+)', output)
        return raw_iface

    def detect_iface(self, nexthop, vrf):
        iface = ''
        if vrf == 'default':
            output = ssh_connect.send_command(f'show ip route {nexthop}')
        else:
            output = ssh_connect.send_command(f'show ip route  vrf {vrf} {nexthop}')
        raw_iface = self.raw_iface(output)
        iface = raw_iface[0][-1].strip(',')
        return iface
    
    def detect_p2p_iface(self, ip):
        output = ssh_connect.send_command(f'show ip interface brief | inc {ip}').split(' ')
        p2p_iface = output[0]
        return p2p_iface

    def acl_command(self, aclname):
        acl = ssh_connect.send_command(f'show access-l {aclname}').strip().split('\n')
        return acl

    def detect_acl(self, iface, x):
        #x - in or out
        output = ssh_connect.send_command(f'show run int {iface}')
        rawacl = re.findall(f'(ip access-group) (\S+|\s+) {x}', output)
        if rawacl:
            aclname = rawacl[0][-1]
            acl = self.acl_command(aclname)
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

    def raw_iface(self, output):
        raw_iface = re.findall('(directly connected,) (\S+|\s+)', output)
        return raw_iface

    def get_addr_raw(self, output):
        self.addr_raw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|not in table|directly connected|Null)", output))
        return self.addr_raw

    def get_nexthop(self, addr_raw):
        nexthop = addr_raw[1]
        return nexthop

    def acl_command(self, aclname):
        acl = ssh_connect.send_command(f"show ip access-l {aclname}").strip().split('\n')
        return acl


class Nexus (Device):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def __str__(self):
        return 'Nexus device'
    
    def show_vrf(self, ip, vrf):
        self.output = ssh_connect.send_command(f'show ip route {ip} vrf {vrf}')
        return self.output

    def detect_iface(self, nexthop, vrf):
        self.vrf = vrf
        if self.vrf == 'default':
            output = ssh_connect.send_command(f'show ip route {nexthop}')
        else:
            output = ssh_connect.send_command(f'show ip route {nexthop} vrf {self.vrf}')
        raw_iface = re.findall('(\*via) (\S+|\s+) (\S+|\s+)', output)
        iface = raw_iface[0][-1].strip(',')
        return iface
    
    def detect_p2p_iface(self, ip):
        output = ssh_connect.send_command(f'show ip interface brief vrf all | inc {ip}').split(' ')
        p2p_iface = output[0]
        return p2p_iface
    
# username = ''
# password = ''




first_hop_vrf = 'default'

p2p_iface = ''
vrf = first_hop_vrf

host_ip = '' # Parameter for Cisco ASA


def find_host_name():
    is_enabled = True
    command = ssh_connect.find_prompt()
    if '>' in command:
        is_enabled = False
    hostname = str(ssh_connect.find_prompt())[:-1]
    return is_enabled, hostname

def run(username, password, prot, src, dst, dst_port, gw, vrf):
    is_first_hop = True
    global ssh_connect, device, results, host_ip
    host_ip = src
    results = []
    device = gw
    result_index = 0
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
            yield {'index': result_index,'hostname': device}
            yield {'index': result_index, 'endmessage': f'Cant connect to {device}'}
            results.append({'endmessage': f'Cant connect to {device}'})
            return results
        
        # First of all we adding current hostname to results
        is_enabled, hostname = find_host_name()
        yield {'index': result_index,'hostname': hostname}

        if is_enabled == False:
            ssh_connect.enable()
            print(str(ssh_connect.find_prompt()))
        
        # Detect version of network device
        d = Version.detect_version()

        global p2p_iface, idc, dstidc
        
        # If device is not first hop, we detect p2p interface and vrf
        if is_first_hop == False:
            p2p_iface = d.detect_p2p_iface(dstnexthop)
            v = Vrf(p2p_iface)
            vrf = v.detect_vrf()
        yield {'index': result_index,'vrf': vrf}

        # Detect source interface
        nexthop, idc = d.detect_next_hop(src, vrf)
        if nexthop == None:
            # addToResults('endmessage', 'No further route in this VRF', result_index)
            yield {'index': result_index, 'endmessage': 'No further route in this VRF'}
            return results
        srciface = d.detect_iface(nexthop, vrf)
        yield {'index': result_index, 'srciface': srciface}

        # Detect access-list on source interface
        try:
            aclname, acl = d.detect_acl(srciface, 'in')
            yield {'index': result_index, 'srcaclname': aclname}
        except Exception:
            traceback.print_exc()
            exit() 

        # Check if we can pass access-list
        if acl == 'noacl':
            yield {'index': result_index, 'srcresult': 'PASSED, no access-list'}
        else:
            yield {'index': result_index, 'srcresult': compare(acl, src, dst, dst_port, prot)}

        # Detect outgoing interface and next hop
        d.is_directly_connected = False
        dstnexthop, dstidc = d.detect_next_hop(dst, vrf)
        if dstnexthop == None:
            yield {'index': result_index, 'endmessage': 'No further route in this VRF'}
        dstiface = d.detect_iface(dstnexthop, vrf)
        yield {'index': result_index, 'dstiface': dstiface}

        # Detect access-list on destination interface
        try:
            aclname, acl = d.detect_acl(dstiface, 'out')
            yield {'index': result_index, 'dstaclname': aclname}
        except Exception:
            print('Wrong destination ip!')
            exit()

        # Check if we can pass access-list
        if acl == 'noacl':
            yield {'index': result_index, 'dstresult': 'PASSED, no access-list'}
        else:
            yield {'index': result_index, 'dstresult': compare(acl, src, dst, dst_port, prot)}
        
        # If destination is directly connected - finish
        if dstidc == True:
            yield {'index': result_index, 'endmessage': 'Target is directly connected'}
            result_index += 1
            print(results)
            return results
        
        # Detect management ip of next hop
        device = findmgmt(dstnexthop)
        yield {'index': result_index, 'nexthop': device}
        is_first_hop = False
        v = Vrf(p2p_iface)
        result_index += 1
    else:
        addToResults('endmessage', 'DONE', result_index)
        return results




if __name__ == '__main__':
    results = run(username, password, prot, addr(src), addr(dst), dst_port, gw, vrf)
    print(results)