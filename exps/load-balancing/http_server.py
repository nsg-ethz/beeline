import http.server
import socketserver
import argparse
import socket
import time
import threading

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        message = f"Hello from {name}!\n"

        self.protocol_version = "HTTP/1.1"
        self.close_connection = False
        self.send_response(200)
        self.send_header("Content-Length", len(message))
        self.end_headers()

        self.wfile.write(bytes(message, "utf8"))
        # serve up an infinite stream
        # i = 0
        # while True:
        #     self.wfile.write("%i " % i)
        #     time.sleep(0.1)
        #     i += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Custom HTTP Server')
    parser.add_argument("-a", "--address", required=True, type=str, help="Address to bind the server to")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Port to bind the server to")
    parser.add_argument("-n", "--name", required=True, type=str, help="Name of the server to print out")

    args = parser.parse_args()
    name = args.name
    address = args.address
    port = args.port

    Handler = RequestHandler

    # Create ONE socket.
    addr = (address, port)
    sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(addr)
    sock.listen(5)

    # Launch 10 listener threads.
    class Thread(threading.Thread):
        def __init__(self, i):
            threading.Thread.__init__(self)
            self.i = i
            self.daemon = True
            self.start()
        def run(self):
            httpd = socketserver.TCPServer(addr, RequestHandler, False)

            # Prevent the HTTP server from re-binding every handler.
            # https://stackoverflow.com/questions/46210672/
            httpd.socket = sock
            httpd.server_bind = self.server_close = lambda self: None

            httpd.serve_forever()
    [Thread(i) for i in range(10)]
    time.sleep(9e9)

    # socketserver.TCPServer.allow_reuse_address = True
    # with socketserver.TCPServer((address, port), Handler) as httpd:
    #     print(f"serving at address {address} and port {port}")
    #     httpd.serve_forever()