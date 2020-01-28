import socket
import sys
import netifaces as ni

if len(sys.argv) < 2:
    print("Usage: %s <file>" % sys.argv[0])
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
server_address = (address, 8888)
print('starting up on %s port %s' % server_address)
sock.bind(server_address)

sock.listen(1)

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
