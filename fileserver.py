#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer

class HttpFileServer(BaseHTTPRequestHandler):

    def __init__(self):
        self.logRequests = False
        self.files = { }

    def addFile(self, name, data):
        if isinstance(data, str):
            data = data.encode("UTF-8")
        if not name.startswith("/"):
            name = "/" + name
        self.files[name.strip()] = data

    def do_GET(self):
        if self.path in self.files:
            data = self.files[self.path]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        if self.logRequests:
            BaseHTTPRequestHandler.log_message(format, *args)
