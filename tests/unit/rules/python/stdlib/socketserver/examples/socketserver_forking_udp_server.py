# level: WARNING
# start_line: 21
# end_line: 21
# start_column: 39
# end_column: 51
import socketserver


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print(f"{self.client_address[0]} wrote:")
        print(data)
        socket.sendto(data.upper(), self.client_address)


if __name__ == "__main__":
    HOST = ""
    PORT = 9999
    with socketserver.ForkingUDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()
