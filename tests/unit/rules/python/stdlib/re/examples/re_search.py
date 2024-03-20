# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 10
# end_column: 17
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.search(pattern, string)
