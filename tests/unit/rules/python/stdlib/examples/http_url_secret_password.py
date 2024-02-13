# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 11
# end_column: 49
import http.client


host = "example.com"
conn = http.client.HTTPSConnection(host)
conn.request(
    "GET", "/path?password=abc123&otherParam=123", headers={"Host": host}
)
response = conn.getresponse()
