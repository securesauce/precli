# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 41
# end_column: 46
import requests


session = requests.Session()
session.post("https://localhost", verify=False)
