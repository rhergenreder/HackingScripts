import random
import socket
import netifaces as ni
import sys
from pwn import *

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

class Stack:
    def __init__(self, startAddress):
        self.buffer = b""
        self.address = startAddress

    def pushString(self, data):
        addr = self.address
        data = pad(data.encode() + b"\x00", 8)
        self.buffer += data
        self.address += len(data)
        return addr

    def pushAddr(self, addr):
        ptr = self.address
        data = p64(addr)
        self.buffer += data
        self.address += len(data)
        return ptr

    def pushArray(self, arr):
        addresses = []
        for arg in arr:
            arg_addr = self.pushString(arg)
            addresses.append(arg_addr)
        addresses.append(0x0)

        addr = self.address
        for arg_addr in addresses:
            self.pushAddr(arg_addr)

        return addr

def genSyscall(elf, syscall, registers):
    rop = ROP(elf)
    registers["rax"] = syscall
    for t in rop.setRegisters(registers):
        value = t[0]
        gadget = t[1]
        if type(gadget) == pwnlib.rop.gadgets.Gadget:
            rop.raw(gadget.address)
            for reg in gadget.regs:
                if reg in registers:
                    rop.raw(registers[reg])
                else:
                    rop.raw(0)

    syscall_gadget = "syscall" if elf.arch == "amd64" else "int 0x80"
    rop.raw(rop.find_gadget([syscall_gadget]).address)
    return rop

def pad(x, n):
    if len(x) % n != 0:
        x  += (n-(len(x)%n))*b"\x00"
    return x

if __name__ == "__main__":
    bin = sys.argv[0]
    if len(sys.argv) < 2:
        print("Usage: %s [command]" % bin)
        exit(1)

    command = sys.argv[1]
    if command == "getAddress":
        if len(sys.argv) >= 2:
            print(getAddress(sys.argv[2]))
        else:
            print(getAddress())
    elif command == "pad":
        if len(sys.argv) >= 3:
            n = 8
            if len(sys.argv) >= 4:
                n = int(sys.argv[3])
            print(pad(sys.argv[2].encode(), n))
        else:
            print("Usage: %s pad <str> [n=8]" % bin)
