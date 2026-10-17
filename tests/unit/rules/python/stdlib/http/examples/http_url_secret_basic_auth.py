# level: ERROR
# start_line: 13
# end_line: 13
# start_column: 4
# end_column: 76
import http.client


host = "example.com"
conn = http.client.HTTPSConnection(host)
conn.request(
    "GET",
    "https://user:pass@example.com:443/path/to/resource?query=value#section",
    headers={"Host": host},
)
response = conn.getresponse()
