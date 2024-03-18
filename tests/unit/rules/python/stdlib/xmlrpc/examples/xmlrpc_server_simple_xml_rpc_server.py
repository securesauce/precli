# level: WARNING
# start_line: 15
# end_line: 15
# start_column: 25
# end_column: 39
from xmlrpc.server import SimpleXMLRPCRequestHandler
from xmlrpc.server import SimpleXMLRPCServer


def run(
    server_class: SimpleXMLRPCServer,
    handler_class: SimpleXMLRPCRequestHandler,
):
    server_address = ("0.0.0.0", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
