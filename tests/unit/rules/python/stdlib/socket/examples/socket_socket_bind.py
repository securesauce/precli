# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 7
# end_column: 15
from socket import *


s = socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 80))
s.listen()
