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

g_verbose = True

DEFAULT_PASS = "student"

class Computer:
    def __init__(self, ip, ssh_port):
        # ip address of the machine
        self.ip = ip
        # port where SSH server is listening
        self.ssh_port = ssh_port
        # initialize as empty dict
        # keys = accountName
        # values = password
        self.accounts = {}

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
    ForwardServer(('', local_port), SubHander).serve_forever()

def verbose(s):
    if g_verbose:
        print(s)

def get_host_port(data):
    args = data.split(":")
    args[1] = int(args[1])
    return args

def begin_attack(client, comp_queue):
    print "Beginning attack"
    verbose("Connecting to ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(server[0], server[1], username=options.user, key_filename=options.keyfile, look_for_keys=options.look_for_keys, password=password)
    except Exception as e:
        print('*** Failed to connect to %s:%d: %r' % (server[0], server[1], e))


    verbose('Now forwarding port %d to %s:%d ...' % (options.port, remote[0], remote[1]))

    try:
        forward_tunnel(options.port, remote[0], remote[1], client.get_transport())
    except KeyboardInterrupt:
        print('C-c: Port forwarding stopped.')


if __name__ == "__main__":
    # init paramiko
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    
