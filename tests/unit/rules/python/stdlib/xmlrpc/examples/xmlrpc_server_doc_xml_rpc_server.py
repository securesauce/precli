# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 25
# end_column: 39
from xmlrpc.server import DocXMLRPCRequestHandler
from xmlrpc.server import DocXMLRPCServer


def run(server_class: DocXMLRPCServer, handler_class: DocXMLRPCRequestHandler):
    server_address = ("::", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
