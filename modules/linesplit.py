import re
import ipaddress
from modules.portreplace import port_replace

addr = ipaddress.ip_address # Слегка сократим имена функций
net = ipaddress.ip_network

class LineSplit:
# Разбираем строку из аксесс-листа

    def convert_to_cidr(self, ip, mask):
        # Преобразуем маску в CIDR
        network = ipaddress.ip_network(f'{ip}/{mask}', strict=False)
        return str(network)

    def acl_addr(self, line):
        global _line
        _line = line
        z = ''
        acl_src = ''
        acl_dst = ''
        port_line = ''
        ip_mask_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')
        ip_addresses = ip_mask_pattern.findall(_line)
        results = []
        for match in ip_addresses:
            if match[0] and match[1]:
                try:
                    cidr = self.convert_to_cidr(match[0], match[1])
                    results.append(cidr)
                except:
                    results.append(f'{match[0]}/{match[1]}')
                    print('DEBUG convert_to_cidr: Не могу разобрать строку', line)      
            elif match[2]:  # Формат CIDR
                results.append(match[2])
        try:
            acl_src = net(results[0])
            acl_dst = net(results[1])
        except:
            acl_src = results[0]
            acl_dst = results[1]
            # print("DEBUG acl_addr: Не могу разобрать строку", line)
            # pass
        return acl_src, acl_dst
    
    def check_port(self, line, port_to_check):
        # Регулярное выражение для поиска портов назначения после 'eq' или в диапазоне
        port_pattern = r'\beq\s+([\d\s,]+)\b|\brange\s+(\d+)\s+(\d+)\b'
        port_to_check = int(port_to_check)  # Приводим к целому числу для сравнения
        is_port_found = False

        # Ищем порты назначения в строке
        line = line.split(' ')
        for item in line:
            x = line.index(item)
            line[x] = str(port_replace(item))
        line = ' '.join(line)

        matches = re.findall(port_pattern, line)
        for match in matches:
            eq_ports = match[0]
            range_start = match[1]
            range_end = match[2]

            # Проверяем порты, указанные через eq
            if eq_ports:
                for port in re.split(r'[\s,]+', eq_ports):
                    if port.isdigit() and int(port) == port_to_check:
                        is_port_found = True
                        break
            
            # Проверяем диапазон портов
            if range_start and range_end:
                if int(range_start) <= port_to_check <= int(range_end):
                    is_port_found = True
                    break

            if is_port_found:
                break

        return is_port_found  # Возвращаем результат проверки

    

if __name__ == '__main__':
    line_split()