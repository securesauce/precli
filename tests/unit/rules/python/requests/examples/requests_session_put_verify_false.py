# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 40
# end_column: 45
import requests


session = requests.Session()
session.put("https://localhost", verify=False)
