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

    def validate_protocol(self, protocol):
        protocols = ['tcp', 'udp', 'ip', 'icmp']
        if protocol not in protocols:
            self.errors['protocol'] = 'Error'
        
        
    def validate_ip(self, srcaddress, dstaddress):
        try:
            addr(srcaddress)
        except:
            self.errors['srcaddress'] = 'Error'
        try:
            addr(dstaddress)
        except:
            self.errors['dstaddress'] = 'Error'
        
    
    def validate_port(self, port):
        try:
            if port and 0 <= int(port) <= 65535:
                pass
            else:
                self.errors['port'] = 'Error'    
        except:
            self.errors['port'] = 'Error'
        
    def validate_gw(self, gw):
        if str(gw) and 1 < len(gw) < 50:
            pass
        else:
            self.errors['gw'] = 'Error'

    def validate_vrf(self, vrf):
        if str(vrf) and 1 < len(vrf) < 50:
            pass
        else:
            self.errors['vrf'] = 'Error'


def validate_all(prot, srcaddress, dstaddress, port, gw, vrf):
    v = Validate()
    v.validate_protocol(prot)
    v.validate_ip(srcaddress, dstaddress)
    v.validate_port(port)
    v.validate_gw(gw)
    v.validate_vrf(vrf)
    return v.errors


if __name__ == '__main__':
    print(validate_all(prot, srcaddress, dstaddress, port, gw, vrf))