def obj_group_replace (line, name, item):
    '''Функция заменяет имя object-group в строке на ip-адреса'''
    lineList = line.split()
    for i in lineList:
        if i == name:
            lineList[lineList.index(i)] = item
            line = ' '.join(lineList)
            return line
        
if __name__ == '__main__':
    obj_group_replace(line, name, item)