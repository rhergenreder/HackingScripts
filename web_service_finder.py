#!/usr/bin/env python

import re
import sys
import argparse
import requests
import urllib.parse
from bs4 import BeautifulSoup

class WebServicecFinder:

    def __init__(self, args):
        self.parseUrl(args.url)
        self.parseCookies(args.cookie)
        self.headers = { }
        self.session = requests.Session()
        self.verbose = args.verbose

        if args.user_agent:
            self.headers["User-Agent"] = args.user_agent

    def parseUrl(self, url):
        parts = urllib.parse.urlparse(url)
        if parts.scheme == '':
            self.url = "http://" + url
            self.scheme = "http"
        elif parts.scheme not in ["http","https"]:
            print("[-] Unsupported URL scheme:", parts.scheme)
            exit(1)
        else:
            self.url = url
            self.scheme = parts.scheme

    def resolve(self, uri):
        if uri is None or uri.strip() == "":
            return self.url
        elif urllib.parse.urlparse(uri).scheme != "":
            return uri

        target = self.url
        if not target.endswith("/"):
            target += "/"
        if uri.startswith("/"):
            uri = uri[1:]

        return target + uri

    def do_get(self, uri, **args):

        uri = self.resolve(uri)
        if self.verbose:
            sys.stdout.write("GET %s: " % uri)

        res = self.session.get(uri, headers=self.headers, cookies=self.cookies, **args)
        if self.verbose:
            sys.stdout.write("%d %s\n" % (res.status_code, res.reason))

        return res

    def parseCookies(self, cookie_list):
        self.cookies = { }
        if cookie_list:
            for cookie in cookie_list:
                cookie = cookie.strip()
                if "=" in cookie:
                    index = cookie.find("=")
                    key, val = cookie[0:index], cookie[index+1:]
                    self.cookies[key] = val
                else:
                    self.cookies[cookie] = ""

    def scan(self):
        print("[ ] Retrieving:", self.url)

        uri = "/"
        while True:
            startPage = self.do_get(uri, allow_redirects=False)
            if startPage.status_code in [301, 302, 397, 308]:
                uri = startPage.headers["Location"]
                if urllib.parse.urlparse(uri).scheme == "https" and self.scheme == "http":
                    self.url = self.url.replace("http","https",1)
                    self.scheme = "https"

                print("[+] Server redirecting to:", uri)
            else:
                break

        self.analyseHeaders(startPage)
        self.analyseHtml(startPage)
        self.analyseRobots()
        self.analyseSitemap()

    def analyseHeaders(self, res):
        phpFound = False
        banner_headers = ["Server", "X-Powered-By", "X-Runtime", "X-Version"]
        for banner in banner_headers:
            if banner in res.headers:
                phpFound = phpFound or ("PHP" in res.headers[banner])
                print("[+] %s Header: %s" % (banner, res.headers[banner]))
        if not phpFound and "PHPSESSID" in self.session.cookies:
            print("[+] PHP detected, unknown version")

    def printMatch(self, title, match, group=1, version_func=str):
        if match:
            version = "Unknown version" if group is None else version_func(match.group(group))
            print("[+] Found %s: %s" % (title, version))
            return True
        return False

    def collectUrls(self, soup):
        urls = set()
        attrs = ["src","href"]
        tags = ["a","link","script","img"]

        for tag in tags:
            for e in soup.find_all(tag):
                for attr in attrs:
                    if e.has_attr(attr):
                        urls.add(e[attr])

        return urls

    def retrieveMoodleVersion(self, v):
        res = requests.get("https://docs.moodle.org/dev/Releases")
        soup = BeautifulSoup(res.text, "html.parser")
        versionStr = "Unknown"

        for tr in soup.find_all("tr"):
            tds = tr.find_all("td")
            th = tr.find("th")
            if len(tds) == 4 and th and int(tds[1].text.strip()) == v:
                versionStr = th.text.strip()
                if versionStr.startswith("Moodle "):
                    versionStr = versionStr[len("Moodle"):].strip()
                break

        return "%s (%d)" % (versionStr, v)

    def analyseHtml(self, res):
        soup = BeautifulSoup(res.text, "html.parser")

        meta_generator = soup.find("meta", {"name":"generator"})
        if meta_generator:
            print("[+] Meta Generator:", meta_generator["content"].strip())

        footer = soup.find("footer")
        if footer:
            content = footer.text.strip()

            gogs_pattern = re.compile(r"(^|\s)Gogs Version: ([a-zA-Z0-9.-]+)($|\s)")
            go_pattern   = re.compile(r"(^|\s)Go([0-9.]+)($|\s+)")

            self.printMatch("Gogs", gogs_pattern.search(content), 2)
            self.printMatch("Go", go_pattern.search(content), 2)

        moodle_pattern_1 = re.compile(r"^https://download.moodle.org/mobile\?version=(\d+)(&|$)")
        moodle_pattern_2 = re.compile(r"^https://docs.moodle.org/(\d+)/")
        litecart_pattern = re.compile(r"^https://www.litecart.net")
        wordpress_pattern = re.compile(r"/wp-(admin|includes|content)/(([^/]+)/)*(wp-emoji-release.min.js|block-library/style.min.css)\?ver=([0-9.]+)(&|$)")

        urls = self.collectUrls(soup)
        for url in urls:
            self.printMatch("Moodle", moodle_pattern_1.search(url), version_func=lambda v: self.retrieveMoodleVersion(int(v)))
            self.printMatch("Moodle", moodle_pattern_2.search(url), version_func=lambda v: "%d.%d" % (int(v)//10,int(v)%10))
            self.printMatch("Litecart", litecart_pattern.search(url), group=None)
            if self.printMatch("Wordpress", wordpress_pattern.search(url), group=5):
                print("[ ] You should consider using 'wpscan' for further investigations and more accurate results")

    def analyseRobots(self):
        res = self.do_get("/robots.txt", allow_redirects=False)
        if res.status_code in (301,302,404,403):
            print("[-] robots.txt not found or inaccessible")
            return False

    def analyseSitemap(self):
        res = self.do_get("/sitemap.xml", allow_redirects=False)
        if res.status_code in (301,302,404,403):
            print("[-] sitemap.xml not found or inaccessible")
            return False

def banner():
    print("""
,--------.              ,--.  ,--------.             ,--.                   ,--.     ,--.
'--.  .--',---.  ,---.,-'  '-.'--.  .--',---.  ,---. |  |    ,--.  ,--.    /   |    /    \\
   |  |  | .-. :(  .-''-.  .-'   |  |  | .-. || .-. ||  |     \  `'  /     `|  |   |  ()  |
   |  |  \   --..-'  `) |  |     |  |  ' '-' '' '-' '|  |      \    /       |  |.--.\    /
   `--'   `----'`----'  `--'     `--'   `---'  `---' `--'       `--'        `--''--' `--'

   """)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="The target URI to scan to, e.g. http://example.com:8080/dir/")
    parser.add_argument("--proxy", help="Proxy to connect through") # TODO
    parser.add_argument("--user-agent", help="User-Agent to use")
    parser.add_argument("--cookie", help="Cookies to send", action='append')
    parser.add_argument('--verbose', '-v', help="Verbose otuput", action='store_true')

    args = parser.parse_args()

    banner()

    client = WebServicecFinder(args)
    client.scan()
