# acl checker
The script connects to a Cisco device via ssh, and checks if a packet with given parameters will pass access-lists.
Then it finds and connects to a next hop and repeat actions.

<code>
usage: AclChecker [-h] -r PROT -s SRC -d DST -p DPORT -g GW [-v VRF]

Checks if packet with given parameters will pass access-lists on all hops

optional arguments:
  -h, --help            show this help message and exit
  -r PROT, --prot PROT  Protocol [tcp|udp|ip|icmp], etc
  -s SRC, --src SRC     Source ip address
  -d DST, --dst DST     Destination ip address
  -p DPORT, --dport DPORT
                        Destination port
  -g GW, --gw GW        Gateway (where to start from)
  -v VRF, --vrf VRF     VRF on first hop (optional)

Example: aclchecker.py -r tcp -s 192.168.1.10 -d 172.16.10.5 -p 443 -g ag-of-1
</code>
Requirements:
python3, ipaddress, netmiko, getpassw
