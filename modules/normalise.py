import re
from modules.hostreplace import hostReplace
from modules.objgroupreplace import objGroupReplace


def normalise(acl, ssh_connect):
    '''Приведение ip адресов в строках к единому виду'''
    acl_clean = []

    for line in acl:
        line = line.replace('host ', '255.255.255.255 ').replace('any', '0.0.0.0 0.0.0.0')
        if "255.255.255.255" in line:
            line = hostReplace(line)
        lineList = line.split()
        if "object-group" in line or "addrgroup" in line:
            objGroupFinder = re.finditer(r'object-group (\S+)|addrgroup (\S+)', line)
            objGroupNames = []
            for i in objGroupFinder:
                objGroupNames.append(i.group(1))
            objGroups = {}
            for i in objGroupNames:
                objgroupItemsRaw = ssh_connect.send_command(f"show object-group name {i}").replace("host", "255.255.255.255")
                objgroupItemsRaw = hostReplace(objgroupItemsRaw)
                objgroupItemsRaw = (re.findall("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", objgroupItemsRaw))
                objgroupItems = []
                x = 0
                for j in range(int(len(objgroupItemsRaw)/2)):
                    objgroupItems.append(' '.join(objgroupItemsRaw[x:x+2]))
                    x += 2
                objGroups[i] = objgroupItems
            tempAcl = []
            if len(objGroupNames) == 1:
                for item in objgroupItems:
                    acl_clean.append(objGroupReplace(line, objGroupNames[0], item).replace("object-group", ""))
            else:
                for item in objgroupItems:
                    tempAcl.append(objGroupReplace(line, objGroupNames[0], item))
                for i in tempAcl:
                    for item in objgroupItems:
                        acl_clean.append(objGroupReplace(i, objGroupNames[1], item).replace("object-group", ""))
        else:
            acl_clean.append(line.strip('\n'))
    return acl_clean

if __name__ == "__main__":
    normalise(acl)