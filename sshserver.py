import socket
import select
import threading
import paramiko

class ParamikoConnection(paramiko.ServerInterface):
    def __init__(self, server):
        self.event = threading.Event()
        self.server = server
        
    def check_channel_request(self, kind, chanid):
        print("check_channel_request", kind, chanid)
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_auth_password(self, username, password):
        if self.server.on_ssh_login:
            return self.server.on_ssh_login(username, password)

        print("check_auth_password", username, password)
        return paramiko.AUTH_SUCCESSFUL

class SSHServer:

    def __init__(self, addr='0.0.0.0', port=22):
        self.server_address = addr
        self.listen_port = port
        self.listen_socket = None
        self.listen_thread = None
        self.client_sockets = []
        self.transports = []
        self.verbose = True
        self.on_message = None
        self.is_running = True
        self.private_key = None

        # hooks
        self.on_ssh_login = None


    def load_private_key_from_file(self, path):
        with open(path, "r") as f:
            self.private_key = paramiko.RSAKey.from_private_key(f)

    def start(self):

        if self.private_key is None:
            self.private_key = paramiko.RSAKey.generate(2048)

        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setblocking(False)
        self.listen_socket.bind((self.server_address, self.listen_port))
        self.listen_socket.listen()
        if self.verbose:
            print(f"SSH server running on: {self.server_address}:{self.listen_port}")
        try:
            while self.is_running:
                try:
                    client_socket, client_address = self.listen_socket.accept()
                    if self.verbose:
                        print("Incoming connection:", client_address)
                    self.client_sockets.append(client_socket)
                    transport = paramiko.Transport(client_socket)
                    transport.add_server_key(self.private_key)
                    paramiko_connection = ParamikoConnection(self)
                    transport.start_server(server=paramiko_connection)
                    self.transports.append(transport)

                except BlockingIOError:
                    pass
        finally:
            self.listen_socket.close()

    def start_background(self):
        self.listen_thread = threading.Thread(target=self.start)
        self.listen_thread.start()
        return self.listen_thread

    def close(self):
        if self.listen_socket:
            self.listen_socket.shutdown(socket.SHUT_RDWR)
        for sock in self.client_sockets:
            sock.close()

    def stop(self):
        self.is_running = False
        self.close()
        if self.listen_thread:
            self.listen_thread.join()
