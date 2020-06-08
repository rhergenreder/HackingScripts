import random
import socket
import netifaces as ni
import sys

def getAddress(interface="tun0"):
    if not interface in ni.interfaces():
        interfaces = ni.interfaces()
        interfaces.remove('lo')
        interface = interfaces[0]

    addresses = ni.ifaddresses(interface)
    address = addresses[ni.AF_INET][0]["addr"]
    return address

def openServer(address, ports=None):
    listenPort = None
    retry = True
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while retry:

        if isinstance(ports, int):
            listenPort = ports
            retry = False
        elif isinstance(ports, range):
            listenPort = random.randint(ports[0],ports[-1])
        elif ports is None:
            listenPort = random.randint(10000,65535)

        try:
            sock.bind((address, listenPort))
            sock.listen(1)
            return sock
        except Exception as e:
            if not retry:
                print("Unable to listen on port %d: %s" % (listenPort, str(e)))
            raise e

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s [command]" % sys.argv[0])
        exit(1)

    if sys.argv[1] == "getAddress":
        if len(sys.argv) > 2:
            print(getAddress(sys.argv[2]))
        else:
            print(getAddress())
