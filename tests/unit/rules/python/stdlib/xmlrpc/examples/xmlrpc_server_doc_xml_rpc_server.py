# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 25
# end_column: 39
from xmlrpc.server import DocXMLRPCServer


def run(server_class: DocXMLRPCServer):
    server_address = ("::", 8000)
    httpd = server_class(server_address, allow_none=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run(DocXMLRPCServer)
