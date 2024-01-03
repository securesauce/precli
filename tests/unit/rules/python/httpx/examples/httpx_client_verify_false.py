# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 29
# end_column: 34
import httpx


client = httpx.Client(verify=False)
response = client.get("https://localhost")
