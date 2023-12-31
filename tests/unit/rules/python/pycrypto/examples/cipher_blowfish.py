# level: ERROR
# start_line: 14
# end_line: 14
# start_column: 18
# end_column: 21
from Crypto import Random
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA


key = b"Very long and confidential key"
nonce = Random.new().read(16)
tempkey = SHA.new(key + nonce).digest()
cipher = Blowfish.new(tempkey)
msg = nonce + cipher.encrypt(b"Open the pod bay doors, HAL")
