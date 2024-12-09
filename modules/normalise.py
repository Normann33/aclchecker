import re
from modules.hostreplace import host_replace
from modules.objgroupreplace import obj_group_replace


def normalise(acl, ssh_connect):
    '''Приведение ip адресов в строках к единому виду'''
    acl_clean = []

    for line in acl:
        if 'remark' in line or 'Extended IP access' in line or 'Access' in line or 'elements' in line:
            continue
        if 'access-list' in line:
            line = ' '.join(line.split()[3::])
        if 'host' in line:
            line = host_replace(line)
        line = line.replace('host', '255.255.255.255').replace('any4', '0.0.0.0 0.0.0.0').replace('any', '0.0.0.0 0.0.0.0')
        if 'object-group' in line or 'addrgroup' in line:
            obj_group_finder = re.finditer(r'object-group (\S+)|addrgroup (\S+)', line)
            obj_group_names = []
            for i in obj_group_finder:
                obj_group_names.append(i.group(1))
            obj_groups = {}
            for i in obj_group_names:
                objgroup_items_raw = ssh_connect.send_command(f'show object-group name {i}').replace('host', '255.255.255.255')
                objgroup_items_raw = host_replace(objgroup_items_raw)
                objgroup_items_raw = (re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', objgroup_items_raw))
                objgroup_items = []
                x = 0
                for j in range(int(len(objgroup_items_raw)/2)):
                    objgroup_items.append(' '.join(objgroup_items_raw[x:x+2]))
                    x += 2
                obj_groups[i] = objgroup_items
            temp_acl = []
            if len(obj_group_names) == 1:
                for item in objgroup_items:
                    acl_clean.append(obj_group_replace(line, obj_group_names[0], item).replace('object-group', ''))
            else:
                for item in objgroup_items:
                    temp_acl.append(obj_group_replace(line, obj_group_names[0], item))
                for i in temp_acl:
                    for item in objgroup_items:
                        acl_clean.append(obj_group_replace(i, obj_group_names[1], item).replace('object-group', ''))
        else:
            acl_clean.append(line.strip('\n'))
    return acl_clean

if __name__ == '__main__':
    normalise(acl)