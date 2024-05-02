# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 25
# end_column: 39
from xmlrpc.server import SimpleXMLRPCServer


def run(server_class: SimpleXMLRPCServer):
    server_address = ("0.0.0.0", 8000)
    httpd = server_class(server_address, allow_none=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run(SimpleXMLRPCServer)
