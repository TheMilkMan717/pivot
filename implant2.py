import os

f = open("servers.txt", "r")
computer = f.readlines()
f.close()

for c in computers:
    comp = c.split(":")
    host = comp[0]
    port = comp[1]
shit = "python demo.py -p 9050 -u root -P student -r %s:%s" % (host, port)
os.system(shit)
