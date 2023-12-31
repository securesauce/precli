# level: ERROR
# start_line: 14
# end_line: 14
# start_column: 18
# end_column: 21
from Cryptodome import Random
from Cryptodome.Cipher import Blowfish
from Cryptodome.Hash import SHA


key = b"Very long and confidential key"
nonce = Random.new().read(16)
tempkey = SHA.new(key + nonce).digest()
cipher = Blowfish.new(tempkey)
msg = nonce + cipher.encrypt(b"Open the pod bay doors, HAL")
