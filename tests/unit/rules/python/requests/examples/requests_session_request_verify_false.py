# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 51
# end_column: 56
import requests


session = requests.Session()
session.request("GET", "https://localhost", verify=False)
