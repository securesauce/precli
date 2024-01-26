# level: NONE
import logging.config


def validate(recv: bytes):
    return recv


thread = logging.config.listen(verify=validate)
