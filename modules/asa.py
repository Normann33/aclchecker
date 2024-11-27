from netmiko import ConnectHandler
import ipaddress
import re
from modules import normalise


class Asa():
    def __init__(self, ssh_connect, ip, *args) -> None:
        super().__init__()
        self.host_ip=ip
        self.ssh_connect = ssh_connect
        self.best_interface = ''
        self.best_gateway = ''
        self.isDirectlyConnected = False

    def getNexthop(self, addrRaw):
        pass



    def detectNextHop(self, host_ip, vrf):

        try:
            self.ssh_connect.enable()  # Вход в привилегированный режим
            print(str(self.ssh_connect.find_prompt())[:-1])

            # Получаем информацию о маршрутах
            command = "show route"
            output = self.ssh_connect.send_command(command)

            self.best_interface = None
            best_mask_length = -1

            # Парсинг вывода для нахождения сети
            pattern = r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\[.*?\]\s+via\s+(\d{1,3}(?:\.\d{1,3}){3}),\s*(\w+)$"
            routeMatches = re.findall(pattern, output, re.MULTILINE)

            # Проверяем, принадлежит ли IP-адрес этой сети
            for i in routeMatches:
                network_obj = ipaddress.ip_network(i[0] + '/' + i[1])
                if ipaddress.ip_address(host_ip) in network_obj:
                    mask_length = network_obj.prefixlen
                    # Сравниваем маски, чтобы найти наиболее точную
                    if mask_length > best_mask_length:
                        best_mask_length = mask_length
                        self.best_interface = i[3]
                        best_network = network_obj
                        self.best_gateway = i[2]
            if self.best_interface:
                output = self.ssh_connect.send_command(f'show route {self.best_interface} {host_ip}')
                if 'directly connected' in output:
                    self.isDirectlyConnected = True
                return self.best_gateway, self.isDirectlyConnected
            else:
                return "Интерфейс не найден"

        except Exception as e:
            return f"Ошибка при подключении или выполнении команды: {e}"
        
    def detectIface(self, host_ip, vrf):
        return self.best_interface

    def aclCommand(self, aclname):
        acl = self.ssh_connect.send_command(f"show access-l {aclname}").strip().split('\n')
        return acl

    def detectAcl(self, iface, x):
        #x - in or out
        output = self.ssh_connect.send_command(f'show run access-group | inc {x} interface {self.best_interface}')
        if output:
            aclname = output.split()[1]
            acl = self.aclCommand(aclname)
            acl = normalise(acl, self.ssh_connect)
        else:
            aclname = 'None'
            acl = 'noacl'
        return aclname, acl

    def detectP2pIface(self, dstnexthop):
        return self.best_interface


if __name__ == '__main__':
    asa = Asa()
    incoming_interface, network, gateway = asa.detectIface(host_ip, asa_ip, username, password)
    asa.detectNextHop()
    print(f"Входящий интерфейс для хоста {host_ip}: {network}, {incoming_interface}, шлюз {gateway}")
