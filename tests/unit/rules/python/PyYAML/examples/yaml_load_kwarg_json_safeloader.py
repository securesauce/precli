# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 28
# end_column: 38
import json

import yaml


yaml.load("{}", Loader=json.SafeLoader)
