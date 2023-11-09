import os

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher


key = os.urandom(32)
algorithm = algorithms.ARC4(key)
cipher = Cipher(algorithm, mode=None)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")
