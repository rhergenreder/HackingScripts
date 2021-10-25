#!/usr/bin/env python

import sys

def generateTemplate(baseUrl):
    template = """#!/usr/bin/env python

import os
import sys
import json
import base64
import requests
import subprocess
import urllib.parse
from bs4 import BeautifulSoup
from hackingscripts import util, fileserver, genRevShell

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "%s" if "LOCAL" not in sys.argv else "http://127.0.0.1:1337"

def request(method, uri, **kwargs):
    if not uri.startswith("/") and uri != "":
        uri = "/" + uri

    client = requests
    if "session" in kwargs:
        client = kwargs["session"]
        del kwargs["session"]

    return client.request(method, BASE_URL + uri, verify=False, allow_redirects=False, **kwargs)

if __name__ == "__main__":
    pass
""" % baseUrl

    return template

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s <URL>" % sys.argv[0])
        exit()

    url = sys.argv[1]
    if "://" not in url:
        url = "http://" + url

    template = generateTemplate(url)
    print(template)
