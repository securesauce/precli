# level: NONE
import ssl


context = ssl.SSLContext()
context.set_ecdh_curve("prime256v1")
