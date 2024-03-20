# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 17
# end_column: 28
import re


IPv6address = r"([A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+"
reg = re.compile(IPv6address)
reg.search("http://[:::::::::::::::::::::::::::::::::::::::]/path")
