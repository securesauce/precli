from cryptography.hazmat.primitives.asymmetric import rsa


public_exponent = 65537
keysize = 1024
rsa.generate_private_key(public_exponent, keysize)
