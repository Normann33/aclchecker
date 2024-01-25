from modules.normalise import normalise
from modules.findmatch import Find_match


green = '<i style="color:green;font-size:12px;font-family:monospace;">'
red = '<i style="color:red;font-size:12px;font-family:monospace;">'

def compare(acl, src, dst, dst_port, prot):
    global _acl
    _acl = acl
    permit = Find_match(acl, 'permit', src, dst, dst_port, prot)
    deny = Find_match(acl, 'deny', src, dst, dst_port, prot)
    if int(permit.split()[0]) < int(deny.split()[0]):
        print('<span class ="passed">    PASSED</span> ' + permit)
    elif int(permit.split()[0]) > int(deny.split()[0]):
        print('<span class ="blocked">    BLOCKED</span> ' + deny)
    else: 
        print ('<span class ="blocked">    BLOCKED</span> by implicit deny')

if __name__ == "__main__":
    compare(acl, src, dst, dst_port, prot)