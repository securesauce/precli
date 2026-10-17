# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 35
# end_column: 39
import telnetlib


telnet = telnetlib.Telnet()
telnet.open("example.com", timeout=None)
