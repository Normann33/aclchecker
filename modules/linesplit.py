import re
import ipaddress
from modules.portreplace import port_replace

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network

class line_split:
# Разбираем строку из аксесс-листа
    def acl_addr(self, line):
        global _line
        _line = line
        z = ''
        acl_src = ''
        acl_dst = ''
        port_line = ''
        ip_addresses = re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", _line)
        try:
            z = line.split().index(ip_addresses[3])
        except Exception:
            print ('DEBUG Не могу разобрать строку', _line)
            pass
        port_line = _line.split()[z::]
        try:
            acl_src = net(ip_addresses[0] + '/' + ip_addresses[1])
            acl_dst = net(ip_addresses[2] + '/' + ip_addresses[3])
        except:
            # print("DEBUG acl_addr: Не могу разобрать строку", line)
            pass 
        return acl_src, acl_dst, port_line
    def check_port(self, line, port):
        global _line
        _line = line
        # port = int(port)
        if 'range' in _line:
            r = _line.index('range')
            x = int(_line[r+1])
            y = int(_line[r+2])
            if x <= int(port) <= y:
                return True
        elif 'eq' in _line:
            for item in _line:
                if item.isalpha():
                    item = port_replace(item)
                if port == str(item):
                    return True
            else:
                return False
        else:
            return False

if __name__ == "__main__":
    line_split()