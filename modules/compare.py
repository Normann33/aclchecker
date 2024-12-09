from modules.normalise import normalise
from modules.findmatch import find_match


def compare(acl, src, dst, dst_port, prot):
    global _acl
    _acl = acl
    permit = find_match(acl, 'permit', src, dst, dst_port, prot)
    deny = find_match(acl, 'deny', src, dst, dst_port, prot)
    if int(permit.split()[0]) < int(deny.split()[0]):
        return f'PASSED,  {permit}'
    elif int(permit.split()[0]) > int(deny.split()[0]):
        return f'BLOCKED,  {deny}'
    else: 
        return 'BLOCKED by implicit deny'

if __name__ == "__main__":
    compare(acl, src, dst, dst_port, prot)