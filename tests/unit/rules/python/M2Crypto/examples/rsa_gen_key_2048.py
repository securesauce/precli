# level: NONE
from M2Crypto import RSA


new_key = RSA.gen_key(2048, 65537)
