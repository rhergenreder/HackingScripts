#!/usr/bin/python

import sys
import os
import util
import argparse

def serve_file(listen_sock, path, forever=False):
    try:
        while True:
            print('[ ] Waiting for a connection')
            connection, client_address = listen_sock.accept()

            try:
                print('[+] Connection from', client_address)

                with open(path, "rb") as f:
                    content = f.read()
                    connection.sendall(content)

                print("[+] File Transfer succeeded")
            finally:
                connection.close()

            if not forever:
                break
    finally:
        listen_sock.close()
            
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="File Transfer using netcat")
    parser.add_argument("--port", type=int, required=False, default=None, help="Listening port")
    parser.add_argument(type=str, dest="path", help="Path to the file you wish to upload")
    args = parser.parse_args()

    path = args.path
    if not os.path.isfile(path):
        print("[-] File not found:", path)
        exit(1)

    address = util.get_address()
    listen_sock = util.open_server(address, args.port)
    if not listen_sock:
        exit(1)

    print("[+] Now listening, download file using:")
    print('nc %s %d > %s' % (address, listen_sock.getsockname()[1], os.path.basename(path)))
    print()

    serve_file(listen_sock, path, forever=True)
