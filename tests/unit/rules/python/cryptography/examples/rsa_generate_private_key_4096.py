# level: NONE
from cryptography.hazmat.primitives.asymmetric import rsa


rsa.generate_private_key(65537, 4096)
