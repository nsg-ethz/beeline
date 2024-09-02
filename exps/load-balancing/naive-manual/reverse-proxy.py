from http.client import HTTPConnection
import requests
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlparse
from argparse import ArgumentParser
import socket
from http.server import BaseHTTPRequestHandler,HTTPServer
import socketserver

SERVER1_URL = "http://10.0.1.1:8000/"
SERVER2_URL = "http://10.0.2.1:8000/"
SERVER3_URL = "http://10.0.3.1:8000/"
SERVER4_URL = "http://10.0.4.1:8000/"

class MyHTTPConnection(HTTPConnection):
    def __init__(self, *args, **kwargs):
        HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_keepalive_linux(self.sock)
        self.sock.connect((self.host, self.port))

class MyHTTPAdapter(requests.adapters.BaseAdapter):
    def __init__(self, host, port):
        self.connection = MyHTTPConnection(host, port)

    def close(self):
        pass

    def send(self, request, **kwargs):
        scheme, location, path, params, query, anchor = urlparse(request.url)
        if ':' in location:
            host, port = location.split(':')
            port = int(port)
        else:
            host = location
            port = 80

        self.connection.request(method=request.method,
                           url=request.url,
                           body=request.body,
                           headers=request.headers)
        r = self.connection.getresponse()
        resp = requests.Response()
        resp.status_code = r.status
        resp.headers = CaseInsensitiveDict(r.headers)
        resp.raw = r
        resp.reason = r.reason
        resp.url = request.url
        resp.request = request
        resp.connection = self.connection
        resp.encoding = requests.utils.get_encoding_from_headers(r.headers)
        requests.cookies.extract_cookies_to_jar(resp.cookies, request, r)
        return resp

def set_keepalive_linux(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

def parse_and_create_adapter(url):
    scheme, location, path, params, query, anchor = urlparse(url)
    if ':' in location:
        host, port = location.split(':')
        port = int(port)
    else:
        print("Error parsing URL for server1")
        return None

    adapt = MyHTTPAdapter(host, port)

    return adapt

def merge_two_dicts(x, y):
    return {**x, **y}

def set_header(hostname):
    headers = {
        'Host': hostname
    }

    return headers

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def do_GET(self, body=True):
        sent = False
        try:
            if 'server1' in self.path:
                hostname = "10.0.1.1:8000"
            elif 'server2' in self.path:
                hostname = "10.0.2.1:8000"
            elif 'server3' in self.path:
                hostname = "10.0.3.1:8000"
            elif 'server4' in self.path:
                hostname = "10.0.4.1:8000"
            else:
                self.send_error(404, 'Unknown URL')
                return

            url = 'http://{}{}'.format(hostname, self.path)
            req_header = self.parse_headers()

            print(url)
            resp = s1.get(url, headers=merge_two_dicts(req_header, set_header(hostname)), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print ('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                print (key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='Port the Reverse Proxy server listens on', default=3000)
    parser.add_argument('-a', '--address', type=str, help='Address the Reverse Proxy bounds to', default='127.0.0.1')
    args = parser.parse_args()

    adapt1 = parse_and_create_adapter(SERVER1_URL)
    adapt2 = parse_and_create_adapter(SERVER2_URL)
    adapt3 = parse_and_create_adapter(SERVER3_URL)
    adapt4 = parse_and_create_adapter(SERVER4_URL)

    # Create a pool of socket objects to be used for every server in the backend
    s1 = requests.Session()
    s1.mount(SERVER1_URL, adapt1)

    s2 = requests.Session()
    s2.mount(SERVER2_URL, adapt2)

    s3 = requests.Session()
    s3.mount(SERVER3_URL, adapt3)

    s4 = requests.Session()
    s4.mount(SERVER4_URL, adapt4)

    Handler = ProxyHTTPRequestHandler

    address = args.address
    port = args.port

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((address, port), Handler) as httpd:
        print(f"serving at address {address} and port {port}")
        httpd.serve_forever()
    