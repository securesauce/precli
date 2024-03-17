# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 4
# end_column: 16
import socket


s = socket.create_server(
    ("::", 8080), family=socket.AF_INET6, dualstack_ipv6=True
)
