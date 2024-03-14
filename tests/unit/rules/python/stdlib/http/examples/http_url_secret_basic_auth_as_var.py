# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 20
# end_column: 23
import http.client


host = "example.com"
conn = http.client.HTTPSConnection(host)
url = "https://user:pass@example.com:443/path/to/resource?query=value#section"
conn.request("GET", url, headers={"Host": host})
response = conn.getresponse()
