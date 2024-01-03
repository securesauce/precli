# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 38
# end_column: 41
import os

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher


key = os.urandom(32)
algorithm = algorithms.IDEA(key)
cipher = Cipher(algorithm, mode=None)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")
