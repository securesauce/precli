# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 9
# end_column: 30
import logging.config


verify = None
thread = logging.config.listen(port=1111, verify=verify)
