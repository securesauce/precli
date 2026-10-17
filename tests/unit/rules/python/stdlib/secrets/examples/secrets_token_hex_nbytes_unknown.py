# level: NONE
import secrets


_SHM_SAFE_NAME_LENGTH = 14
_SHM_NAME_PREFIX = "/psm_"
nbytes = (_SHM_SAFE_NAME_LENGTH - len(_SHM_NAME_PREFIX)) // 2
name = _SHM_NAME_PREFIX + secrets.token_hex(nbytes)
