# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 43
# end_column: 48
import requests


session = requests.Session()
session.delete("https://localhost", verify=False)
