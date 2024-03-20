# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 8
# end_column: 15
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.subn(pattern, print, string)
