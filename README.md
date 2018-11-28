# acl checker
The script connects to a Cisco device via ssh, and checks if a packet with given parameters will pass access-lists.
Then it finds and connects to a next hop and repeat actions.

Usage: ./aclchecker.py protocol, source ip, destination ip, destination port, device ip

Requirements:
python3, ipaddress, netmiko 
