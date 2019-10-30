from os import remove
from sys import argv

try:
    fplain=argv[1]
except:
    print("where's the null sh*ts!")
    exit()

fd = open(fplain, 'r')
data = fd.read()
fd.close()
remove(fplain)
replaced = data.replace("\x00"*50, "")
fd = open(fplain, 'wb')
fd.write(replaced)
fd.close()