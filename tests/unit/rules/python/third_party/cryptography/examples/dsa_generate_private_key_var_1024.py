from cryptography.hazmat.primitives.asymmetric import dsa


keysize = 1024
dsa.generate_private_key(keysize)
