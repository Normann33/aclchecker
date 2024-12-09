
def host_replace(line):
    lineList = line.split()
    indices = [i for i, x in enumerate(lineList) if x == 'host']
    for i in range(len(indices)):
        r = indices[i]
        x = r+1
        lineList[r] = lineList[x]
        lineList[x] = 'host'
    line = ' '.join(lineList)
    return line

if __name__ == '__main__':
    host_replace(line)