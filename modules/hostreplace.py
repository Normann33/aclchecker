
def hostReplace(line):
    lineList = line.split()
    indices = [i for i, x in enumerate(lineList) if x == "255.255.255.255"]
    for i in range(len(indices)):
        r = indices[i]
        x = r+1
        lineList[r] = lineList[x]
        lineList[x] = '255.255.255.255'
    line = ' '.join(lineList)
    return line

if __name__ == "__main__":
    hostReplace(line)