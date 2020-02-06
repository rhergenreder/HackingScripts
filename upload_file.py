import socket
import sys
import os
import netifaces as ni

if len(sys.argv) < 2:
    print("Usage: %s <file> [port]" % sys.argv[0])
    exit(1)

# Create a TCP/IP socket
FILENAME = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

interface = "tun0"
if not interface in ni.interfaces():
    interface = ni.interfaces()[0]

addresses = ni.ifaddresses(interface)
address = addresses[next(iter(addresses))][0]["addr"]

# Bind the socket to the port
port = 8888 if len(sys.argv) < 3 else int(sys.argv[2])
server_address = (address, port)
sock.bind(server_address)
sock.listen(1)
print("Now listening, download file using:")
print('nc %s %d > %s' % (address, port, os.path.basename(FILENAME)))
print()

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        print('connection from', client_address)

        with open(FILENAME, "rb") as f:
            content = f.read()
            connection.sendall(content)

    finally:
        # Clean up the connection
        connection.close()
