import logging.config

verify = None
thread = logging.config.listen(port=1111, verify=verify)
