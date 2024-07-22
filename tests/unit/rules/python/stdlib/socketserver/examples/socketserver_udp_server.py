# level: WARNING
# start_line: 18
# end_line: 18
# start_column: 32
# end_column: 44
import socketserver


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        socket.sendto(data.upper(), self.client_address)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 9999
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()
