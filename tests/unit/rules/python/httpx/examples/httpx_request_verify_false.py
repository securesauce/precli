# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 48
# end_column: 53
import httpx


httpx.stream("GET", "https://localhost", verify=False)
