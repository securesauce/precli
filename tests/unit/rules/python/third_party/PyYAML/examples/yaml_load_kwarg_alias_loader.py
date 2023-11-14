# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 23
# end_column: 29
import yaml
from yaml import Loader as LOADER


yaml.load("{}", Loader=LOADER)
