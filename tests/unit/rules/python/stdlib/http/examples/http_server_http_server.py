# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 25
# end_column: 39
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer


def run(server_class: HTTPServer, handler_class: BaseHTTPRequestHandler):
    server_address = ("", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
