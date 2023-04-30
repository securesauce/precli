import json

import yaml

yaml.load("{}", Loader=json.SafeLoader)
