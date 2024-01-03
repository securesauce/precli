# level: ERROR
# start_line: 14
# end_line: 14
# start_column: 13
# end_column: 16
from Cryptodome import Random
from Cryptodome.Cipher import XOR
from Cryptodome.Hash import SHA


key = b"Very long and confidential key"
nonce = Random.new().read(16)
tempkey = SHA.new(key + nonce).digest()
cipher = XOR.new(tempkey)
msg = nonce + cipher.encrypt(b"Open the pod bay doors, HAL")
