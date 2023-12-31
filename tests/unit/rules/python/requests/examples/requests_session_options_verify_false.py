# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 44
# end_column: 49
import requests


session = requests.Session()
session.options("https://localhost", verify=False)
