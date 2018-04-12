import os

f = open("servers.txt", "r")
computers = f.readlines()
f.close()

for c in computers:
    comp = c.split(":")
    host = comp[0]
    port = comp[1]
shit = "python demo.py -p 9050 -u root -P student -r 10.4.0.3:6969 10.3.0.2:22"
os.system(shit)
