# level: NONE
import ssl


ssl.get_server_certificate(
    ("localhost", 443), ssl_version=ssl.PROTOCOL_TLSv1_2
)
