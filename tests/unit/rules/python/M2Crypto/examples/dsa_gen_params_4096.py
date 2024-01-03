# level: NONE
from M2Crypto import DSA


new_key = DSA.gen_params(4096)
