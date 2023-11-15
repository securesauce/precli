# level: ERROR
# start_line: 15
# end_line: 15
# start_column: 13
# end_column: 16
import os

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes


key = os.urandom(32)
algorithm = algorithms.AES(key)
mode = modes.ECB()
cipher = Cipher(algorithm, mode=mode)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
