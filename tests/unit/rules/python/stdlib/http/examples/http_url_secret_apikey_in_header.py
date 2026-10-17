# level: NONE
import http.client


host = "example.com"
headers = {"X-FullContact-APIKey": "value"}
conn = http.client.HTTPSConnection(host)
conn.request("GET", "/path?otherParam=123", headers=headers)
response = conn.getresponse()
