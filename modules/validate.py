import ipaddress

addr = ipaddress.IPv4Address

# Uncomment below to test module:
# prot = 'tcp'
# srcaddress = '1.1.1.1'
# dstaddress = '2.2.2.2'
# port = '443'
# gw = 'device'
# vrf = 'default'

class Validate():
    def __init__(self):
        self.errors = {}

    def validateProtocol(self, protocol):
        protocols = ['tcp', 'udp', 'ip', 'icmp']
        if protocol not in protocols:
            self.errors['protocol'] = 'Error'
        
        
    def validateIp(self, srcaddress, dstaddress):
        try:
            addr(srcaddress)
        except:
            self.errors['srcaddress'] = 'Error'
        try:
            addr(dstaddress)
        except:
            self.errors['dstaddress'] = 'Error'
        
    
    def validatePort(self, port):
        try:
            if port and 0 <= int(port) <= 65535:
                pass
            else:
                self.errors['port'] = 'Error'    
        except:
            self.errors['port'] = 'Error'
        
    def validateGw(self, gw):
        if str(gw) and 1 < len(gw) < 50:
            pass
        else:
            self.errors['gw'] = 'Error'

    def validateVrf(self, vrf):
        if str(vrf) and 1 < len(vrf) < 50:
            pass
        else:
            self.errors['vrf'] = 'Error'


def validateAll(prot, srcaddress, dstaddress, port, gw, vrf):
    v = Validate()
    v.validateProtocol(prot)
    v.validateIp(srcaddress, dstaddress)
    v.validatePort(port)
    v.validateGw(gw)
    v.validateVrf(vrf)
    return v.errors


if __name__ == '__main__':
    print(validateAll(prot, srcaddress, dstaddress, port, gw, vrf))