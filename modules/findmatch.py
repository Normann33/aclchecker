from modules.linesplit import LineSplit
import ipaddress
import traceback

addr = ipaddress.ip_address
net = ipaddress.ip_network

l1 = LineSplit()

def check_mask(ip_str, network_line):
        # Преобразуем строки в объекты IP
        network_line = network_line.split('/')
        network_str = network_line[0]
        mask_str = network_line[1]
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_address(network_str)
        mask = ipaddress.ip_address(mask_str)

        # Получаем побитовые представления
        ip_bin = int(ip)
        network_bin = int(network)
        mask_bin = int(mask)

        # Проверяем, попадает ли IP в сеть с использованием маски
        return (ip_bin & ~mask_bin) == (network_bin & ~mask_bin)

def check_ip(ip, network):
    try:
        return (addr(ip) in net(network))
    except:
        return check_mask(ip, network)

def find_match(acl, x, src, dst, dst_port, prot):
# Ищем совпадения в access-list-e, x - permit or deny
    for line in acl:
        acl_src, acl_dst = l1.acl_addr(line)
        try:
            if x in line and prot in line and check_ip(src, acl_src) and check_ip(dst, acl_dst) and 'established' not in line and (l1.check_port(line, dst_port) == True or ('eq' not in line and 'range' not in line)) and 'established' not in line:
                return line 
                break
            elif x in line and ' ip ' in line and src in acl_src and dst in acl_dst:
                return line 
                break
        except Exception:
            traceback.print_exc()
            print('    DEBUG: find_match Не могу разобрать строку ', line)
            pass
    else:
        line = '99999 deny ip any any'
        return line        
    
if __name__ == '__main__':
    find_match(acl, x, src, dst, dst_port, prot)