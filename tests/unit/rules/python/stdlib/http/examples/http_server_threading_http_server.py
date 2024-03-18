# level: WARNING
# start_line: 15
# end_line: 15
# start_column: 25
# end_column: 39
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer


def run(
    server_class: ThreadingHTTPServer,
    handler_class: BaseHTTPRequestHandler,
):
    server_address = ("", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
