# level: NONE
import ssl


cert = ssl.get_server_certificate(("example.com", 443), timeout=5.0)
