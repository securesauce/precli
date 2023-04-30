import yaml
from yaml import SafeLoader

yaml.load("{}", Loader=SafeLoader)
