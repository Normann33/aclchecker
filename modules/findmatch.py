from modules.linesplit import line_split
import traceback

l1 = line_split()

def Find_match(acl, x, src, dst, dst_port, prot):
# Ищем совпадения в access-list-e, x - permit or deny
    for line in acl:
        acl_src, acl_dst, port_line = l1.acl_addr(line)
        try:
            if x in line and prot in line and src in acl_src and dst in acl_dst and 'established' not in line and (l1.check_port(port_line, dst_port) == True or ('eq' not in port_line and 'range' not in port_line)) and 'established' not in line:
                return line 
                break
            elif x in line and ' ip ' in line and src in acl_src and dst in acl_dst:
                return line 
                break
        except Exception:
            # traceback.print_exc()
            print('    DEBUG: find_match Не могу разобрать строку ', line)
            pass
    else:
        line = '99999 deny ip any any'
        return line        
    
if __name__ == "__main__":
    Find_match(acl, x)