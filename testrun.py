import webaclcheckerdev
import ipaddress

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network


username = ''
password = ''

gw = ''
src = ''
dst = ''
dst_port = '443'
prot = 'tcp'
vrf = 'default'


for data in webaclcheckerdev.run(username, password, prot, addr(src), addr(dst), dst_port, gw, vrf):
    print(data)
