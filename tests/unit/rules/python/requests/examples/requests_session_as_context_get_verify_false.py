# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 44
# end_column: 49
import requests


with requests.Session() as session:
    session.get("https://localhost", verify=False)
