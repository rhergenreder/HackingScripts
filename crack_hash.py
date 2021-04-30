#!/usr/bin/env python

import sys
import requests
import subprocess
import enum
import re
import tempfile
import base64
import io
from bs4 import BeautifulSoup

HEX_PATTERN = re.compile("^[a-fA-F0-9]+$")
B64_PATTERN = re.compile("^[a-zA-Z0-9+/=]+$")
B64_URL_PATTERN = re.compile("^[a-zA-Z0-9=_-]+$")

class HashType(enum.Enum):

    # MD5
    RAW_MD4 = 900
    RAW_MD5 = 0
    MD5_PASS_SALT = 10
    MD5_SALT_PASS = 20
    WORDPRESS = 400
    DRUPAL7 = 7900

    # SHA1
    RAW_SHA1 = 100
    SHA1_PASS_SALT = 110
    SHA1_SALT_PASS = 120

    # SHA2
    RAW_SHA2_224 = 1300
    RAW_SHA2_256 = 1400
    SHA256_PASS_SALT = 1410
    SHA256_SALT_PASS = 1420
    RAW_SHA2_384 = 10800
    RAW_SHA2_512 = 1700
    SHA512_PASS_SALT = 1710
    SHA512_SALT_PASS = 1720

    # SHA3
    RAW_SHA3_224 = 17300
    RAW_SHA3_256 = 17400
    RAW_SHA3_384 = 17500
    RAW_SHA3_512 = 17600

    # Keccak
    RAW_KECCAK_224 = 17700
    RAW_KECCAK_256 = 17800
    RAW_KECCAK_384 = 17900
    RAW_KECCAK_512 = 18000

    # Ripe-MD
    RAW_RIPEMD_160 = 6000

    # Crypt
    CRYPT_MD5 = 500
    CRYPT_BLOWFISH = 3200
    CRYPT_SHA256 = 7400
    CRYPT_SHA512 = 1800
    CRYPT_APACHE = 1600

    # Windows
    LM   = 3000
    NTLM = 1000
    MSSQL = 1731

    # Kerberos
    KERBEROS_AS_REQ = 7500
    KERBEROS_TGS_REP = 13100
    KERBEROS_AS_REP = 18200

class Hash:

    def __init__(self, hash):
        self.hash = hash
        self.salt = None
        self.isSalted = False
        self.type = []
        self.cracked = None
        self.findType()

    def findType(self):

        raw_hash = self.hash
        if raw_hash[0] == "$":
            crypt_parts = list(filter(None, raw_hash.split("$")))
            crypt_type = crypt_parts[0]
            self.isSalted = len(crypt_parts) > 2
            if crypt_type == "1":
                self.type.append(HashType.CRYPT_MD5)
            elif crypt_type.startswith("2"):
                self.type.append(HashType.CRYPT_BLOWFISH)
            elif crypt_type == "5":
                self.type.append(HashType.CRYPT_SHA256)
            elif crypt_type == "6":
                self.type.append(HashType.CRYPT_SHA512)
            elif crypt_type == "apr1":
                self.type.append(HashType.CRYPT_APACHE)
            elif crypt_type == "krb5tgs":
                self.type.append(HashType.KERBEROS_TGS_REP)
            elif crypt_type == "krb5asreq":
                self.type.append(HashType.KERBEROS_AS_REQ)
            elif crypt_type == "krb5asrep":
                self.type.append(HashType.KERBEROS_AS_REP)
            elif crypt_type == "P":
                self.type.append(HashType.WORDPRESS)
            elif crypt_type == "S":
                self.type.append(HashType.DRUPAL7)
        else:
            self.isSalted = ":" in raw_hash
            if self.isSalted:
                raw_hash, self.salt = raw_hash.split(":")

        # Base64 -> hex
        try:
            if not HEX_PATTERN.match(raw_hash):

                if B64_URL_PATTERN.match(raw_hash):
                    raw_hash = raw_hash.replace("-","+").replace("_","/")
                if B64_PATTERN.match(raw_hash):
                    raw_hash = base64.b64decode(raw_hash.encode("UTF-8")).decode("UTF-8").hex()

                if self.isSalted:
                    self.hash = raw_hash + ":" + self.salt
                else:
                    self.hash = raw_hash
        except:
            pass

        if HEX_PATTERN.match(raw_hash):
            hash_len = len(raw_hash)
            if hash_len == 32:
                if self.isSalted:
                    self.type.append(HashType.MD5_PASS_SALT)
                    self.type.append(HashType.MD5_SALT_PASS)
                else:
                    self.type.append(HashType.RAW_MD5)
                    self.type.append(HashType.RAW_MD4)
                    self.type.append(HashType.NTLM)
                    self.type.append(HashType.LM)
            elif hash_len == 40:
                if self.isSalted:
                    self.type.append(HashType.SHA1_PASS_SALT)
                    self.type.append(HashType.SHA1_SALT_PASS)
                else:
                    self.type.append(HashType.RAW_SHA1)
                    self.type.append(HashType.RAW_RIPEMD_160)
            elif hash_len == 64:
                if self.isSalted:
                    self.type.append(HashType.SHA256_PASS_SALT)
                    self.type.append(HashType.SHA256_SALT_PASS)
                else:
                    self.type.append(HashType.RAW_SHA2_256)
                    self.type.append(HashType.RAW_SHA3_256)
            elif hash_len == 96:
                if not self.isSalted:
                    self.type.append(HashType.RAW_SHA2_384)
                    self.type.append(HashType.RAW_SHA3_384)
                    self.type.append(HashType.RAW_KECCAK_384)
            elif hash_len == 128:
                if self.isSalted:
                    self.type.append(HashType.SHA512_PASS_SALT)
                    self.type.append(HashType.SHA512_SALT_PASS)
                else:
                    self.type.append(HashType.RAW_SHA2_512)
                    self.type.append(HashType.RAW_SHA3_512)
                    self.type.append(HashType.RAW_KECCAK_256)
            elif hash_len == 140:
                if not self.isSalted:
                    seld.type.append(HashType.MSSQL)
                    self.hash = "0x" + raw_hash # TODO: MSSQL requires 0x prefix..
        elif raw_hash.startswith("0x") and HEX_PATTERN.match(raw_hash[2:]) and len(raw_hash) == 140+2:
            seld.type.append(HashType.MSSQL)

        if len(self.type) == 0:
            print("%s: Unknown hash" % self.hash)

if len(sys.argv) < 2:
    print("Usage: %s <file>" % sys.argv[0])
    exit(1)

hashes = [Hash(x) for x in filter(None, [line.strip() for line in open(sys.argv[1],"r").readlines()])]
wordlist = "/usr/share/wordlists/rockyou.txt" if len(sys.argv) < 3 else sys.argv[2]

uncracked_hashes = { }
for hash in hashes:
    if hash.type:
        for t in hash.type:
            if t not in uncracked_hashes:
                uncracked_hashes[t] = []
            uncracked_hashes[t].append(hash)

if len(uncracked_hashes) > 0:
    uncracked_types = list(uncracked_hashes.keys())
    num_types = len(uncracked_types)
    if num_types > 1:
        print("There are multiple uncracked hashes left with different hash types, choose one to proceed with hashcat:")
        print()

        i = 0
        for t,lst in uncracked_hashes.items():
            print("%d.\t%s:\t%d hashe(s)" % (i, str(t)[len("HashType."):], len(lst)))
            i += 1

        # Ask user…
        selected = None
        while selected is None or selected < 0 or selected >= num_types:
            try:
                selected = int(input("Your Choice: ").strip())
                if selected >= 0 and selected < num_types:
                    break
            except Exception as e:
                if type(e) in [EOFError, KeyboardInterrupt]:
                    print()
                    exit()

            print("Invalid input")
        selected_type = uncracked_types[selected]
    else:
        selected_type = uncracked_types[0]

    fp = tempfile.NamedTemporaryFile()
    for hash in uncracked_hashes[selected_type]:
        fp.write(b"%s\n" % hash.hash.encode("UTF-8"))
    fp.flush()

    proc = subprocess.Popen(["hashcat", "-m", str(selected_type.value), "-a", "0", fp.name, wordlist])
    proc.wait()
    fp.close()
