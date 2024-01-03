# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 34
# end_column: 39
import httpx


client = httpx.AsyncClient(verify=False)
response = client.get("https://localhost")
