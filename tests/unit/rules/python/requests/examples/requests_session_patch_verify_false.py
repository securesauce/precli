# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 42
# end_column: 47
import requests


session = requests.Session()
session.patch("https://localhost", verify=False)
