import yaml
from yaml import Loader as LOADER

yaml.load("{}", Loader=LOADER)
