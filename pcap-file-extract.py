import argparse
import os
import re
from abc import ABC, abstractmethod
from scapy.all import *
from hackingscripts import util


class HttpPacket(ABC):
    def __init__(self, version):
        self.version = version
        self.headers = util.CaseInsensitiveDict()
        self.payload = None

    @staticmethod
    def parse(data):
        index = data.index(b"\r\n")
        first_line = data[0:index+2].decode()
        matches_req = re.match(HttpRequest.PATTERN.decode(), first_line)
        matches_res = re.match(HttpResponse.PATTERN.decode(), first_line)
        if matches_req:
            http_packet = HttpRequest(*matches_req.groups())
        elif matches_res:
            http_packet = HttpResponse(*matches_res.groups())
        else:
            return None

        header_end = data.index(b"\r\n\r\n")
        header_buffer = data[index+2:header_end+2].decode()
        http_packet.payload = data[header_end+4:]
        for line in re.findall("([^:]+):\s?(.*)\r\n", header_buffer):
            http_packet.headers[line[0]] = line[1]

        return http_packet

    @abstractmethod
    def get_file_path(self):
        pass


class HttpRequest(HttpPacket):
    PATTERN = b"([A-Z]+) ([^ ]+) HTTP/([0-9.]+)\r\n"

    def __init__(self, method, uri, version):
        super().__init__(version)
        self.method = method
        self.uri = uri

    def __repr__(self):
        return f"{self.method} {self.uri} HTTP/{self.version}, payload=" + util.human_readable_size(len(self.payload))

    def get_file_path(self):
        return self.uri


class HttpResponse(HttpPacket):
    PATTERN = b"HTTP/([0-9.]+) ([0-9]+) (.*)\r\n"

    def __init__(self, version, status_code, status_text):
        super().__init__(version)
        self.status_code = int(status_code)
        self.status_text = status_text
        self.response_to = None

    def get_file_path(self):
        content_disposition = self.headers.get("Content-Disposition", None)
        if content_disposition:
            matches = re.findall(";\s*filename=\"?(.*)\"?(;|$)", content_disposition)
            if matches:
                return matches[0][0]

        if self.response_to:
            return self.response_to.get_file_path()

        return None

    def __repr__(self):
        return f"HTTP/{self.version} {self.status_code} {self.status_text}, payload=" + util.human_readable_size(len(self.payload))

class PacketIterator:
    def __init__(self, connection):
        self.connection = connection
        self.index = 0

    def __iter__(self):
        self.index = 0
        return self

    def __next__(self):
        if self.has_more():
            packet = self.connection.packets[self.index]
            self.index += 1
            return packet
        else:
            raise StopIteration

    def peek(self):
        return None if not self.has_more() else self.connection.packets[self.index]

    def pop(self):
        packet = self.peek()
        if packet:
            self.index += 1
        return packet

    def find_packet(self, pattern, sock_src=None):
        for packet in self.connection.packets[self.index:]:
            self.index += 1
            tcp_packet = packet[TCP]
            ip_hdr = packet[IP]
            packet_src = f"{ip_hdr.src}:{tcp_packet.sport}"
            if sock_src is not None and packet_src != sock_src:
                continue

            payload = bytes(tcp_packet.payload)
            match = re.findall(pattern, payload)
            if match:
                return packet, match[0], packet_src
        return None

    def has_more(self):
        return self.index < len(self.connection.packets)


class TcpConnection:
    def __init__(self, sock_a, sock_b):
        self.sock_a = sock_a
        self.sock_b = sock_b
        self.packets = []
        self._payload_size = 0

    def add_packet(self, packet):
        self.packets.append(packet)
        self._payload_size += len(packet[TCP].payload)

    def get_key(self):
        return TcpConnections._format_key(self.sock_a, self.sock_b)

    def iterator(self):
        return PacketIterator(self)

    def get_other_sock(self, sock):
        return self.sock_a if sock == self.sock_b else self.sock_b

    def __repr__(self):
        return f"{self.get_key()}: {len(self.packets)} packets, {util.human_readable_size(self._payload_size)}"


class TcpConnections:
    def __init__(self):
        self.connections = {}

    def __contains__(self, item: TcpConnection):
        return str(item) in self.connections

    def add(self, element: TcpConnection):
        self.connections[str(element)] = element

    def __getitem__(self, item: TcpConnection):
        return self.connections[str(item)]

    def __iter__(self):
        return iter(self.connections.values())

    @staticmethod
    def _format_key(sock_a, sock_b):
        return f"{sock_a}<->{sock_b}" if sock_a < sock_b else f"{sock_b}<->{sock_a}"

    def get_connection(self, sock_a, sock_b):
        key = self._format_key(sock_a, sock_b)
        return self.connections[key]

    def add_packet(self, sock_src, sock_dst, packet):
        key = self._format_key(sock_src, sock_dst)
        if key not in self.connections:
            self.connections[key] = TcpConnection(sock_src, sock_dst)

        self.connections[key].add_packet(packet)
        return self.connections[key]


class PcapExtractor:
    def __init__(self, pcap_path, output_dir="extracted_files/", filters=None):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        self.filters = filters if filters is not None else []
        self._packets = None

    def _open_file(self):
        # self._packets = pcapkit.extract(fin=self.pcap_path, store=False, nofile=True)
        self._packets = rdpcap(self.pcap_path)

    def extract_all(self):
        pass

    def _apply_filters(self, packets):
        filtered_packets = packets
        for f in self.filters:
            filtered_packets = filter(f, filtered_packets)
        return list(filtered_packets)

    def list(self):
        self._open_file()
        http_packets = self._parse_http_packets()
        filtered_packets = self._apply_filters(http_packets)
        for packet in filtered_packets:
            print(packet)

    def get_http_packet(self, packet_iterator, sock_src, initial_packet):
        http_buffer = bytes(initial_packet[TCP].payload)
        while packet_iterator.has_more():
            next_packet = packet_iterator.peek()
            if sock_src == f"{next_packet[IP].src}:{next_packet[TCP].sport}":
                next_packet = packet_iterator.pop()
                http_buffer += bytes(next_packet[TCP].payload)
            else:
                break

        return HttpPacket.parse(http_buffer)

    def _parse_http_packets(self):

        connections = TcpConnections()
        for packet in self._packets:
            if TCP not in packet:
                continue

            ip_hdr = packet[IP]
            tcp_packet = packet[TCP]
            if len(tcp_packet.payload) == 0:
                continue

            sock_src = f"{ip_hdr.src}:{tcp_packet.sport}"
            sock_dst = f"{ip_hdr.dst}:{tcp_packet.dport}"
            connections.add_packet(sock_src, sock_dst, packet)

        http_packets = []
        for connection in connections:
            packet_iterator = connection.iterator()
            while packet_iterator.has_more():
                request = packet_iterator.find_packet(HttpRequest.PATTERN)
                if not request:
                    continue

                packet, match, sock_src = request
                method = match[0].decode()
                file_name = match[1].decode().rsplit("?")[0]
                http_request_packet = self.get_http_packet(packet_iterator, sock_src, packet)
                http_packets.append(http_request_packet)

                other_sock = connection.get_other_sock(sock_src)
                response = packet_iterator.find_packet(HttpResponse.PATTERN, sock_src=other_sock)
                if not response:
                    continue

                packet, match, sock_src = response
                status_code = match[1].decode()
                http_response_packet = self.get_http_packet(packet_iterator, sock_src, packet)
                http_response_packet.response_to = http_request_packet
                http_packets.append(http_response_packet)

        return http_packets


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to pcap file to extract files from")
    parser.add_argument("-o", "--output-dir", help="Path to destination directory", default="extracted_files/",
                        dest="output_dir")
    parser.add_argument("-l", "--list", help="List available files only", default=False, action="store_true")
    parser.add_argument("-e", "--extract", help="Extract files (default)", default=None, action="store_true")
    parser.add_argument("-ec", "--exclude-codes", help="Exclude http status codes, default: 101,304,403,404",
                        default="101,304,403,404", dest="exclude_codes")
    parser.add_argument("-ic", "--include-codes", help="Limit http status codes", type=str,
                        default="", dest="include_codes")
    parser.add_argument("-fe", "--file-extensions", help="File extensions, e.g. txt,exe,pdf", type=str,
                        default="", dest="file_extensions")
    parser.add_argument("-fn", "--file-name", help="File name, e.g. passwords.txt", type=str,
                        default="", dest="file_name")
    parser.add_argument("-fp", "--file-path", help="File path (uri), e.g. /admin/index.html", type=str,
                        default="", dest="file_path")
    # TODO: ports, ip_addresses...

    args = parser.parse_args()

    filters = [
        lambda p: not isinstance(p, HttpResponse) or p.status_code not in [int(x) for x in args.exclude_codes.split(",")],
    ]

    if args.include_codes:
        filters.append(lambda p: not isinstance(p, HttpResponse) or p.status_code in [int(x) for x in args.include_codes.split(",")])

    if args.file_extensions:
        filters.append(lambda p: os.path.splitext(p.file_name)[1] in args.file_extensions.split(","))

    if args.file_name:
        filters.append(lambda p: os.path.basename(p.get_file_path()) == args.file_name)

    if args.file_path:
        filters.append(lambda p: p.get_file_path() == args.file_path)

    pcap_path = args.file
    if not os.path.isfile(pcap_path):
        print("[-] File not found or not a file:", pcap_path)
        exit(1)

    output_dir = args.output_dir
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        if not os.path.isdir(output_dir):
            print("[-] Output directory is not a directory or does not exist and could not be created:", output_dir)
            exit(2)

    pcap_extractor = PcapExtractor(pcap_path, output_dir, filters)
    if args.list and args.extract:
        print("[-] Can only specify one of list or extract, not both")
        exit(3)
    elif args.list:
        pcap_extractor.list()
    else:
        pcap_extractor.extract_all()
