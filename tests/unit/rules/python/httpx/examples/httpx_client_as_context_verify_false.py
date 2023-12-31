# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 25
# end_column: 30
import httpx


with httpx.Client(verify=False) as client:
    response = client.get("https://localhost")
