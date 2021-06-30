#!/usr/bin/env python

import sys

def generateTemplate(baseUrl):
    template = """#!/usr/bin/env python

import sys
import json
import base64
import requests
from bs4 import BeautifulSoup
from hackingscripts import util, fileserver

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "%s" if "LOCAL" not in sys.argv else "http://127.0.0.1:1337"
USERNAME = "admin"
PASSWORD = "password"

def login(username, password):
    # Template method to create a session
    session = requests.Session()
    post_data = { "username": username, "password": password }
    res = session.post(BASE_URL + "/login", data=post_data, allow_redirects=False)
    if res.status_code != 302 or "Location" not in res.headers or res.headers["Location"] != "/home":
        print("Login failed")
        exit()
    return session

def exploit(session, payload):
    # Template method to exploit an endpoint
    pass

if __name__ == "__main__":
    session = login(USERNAME, PASSWORD)
    exploit(session, "id")
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
