import yaml

SAFE_LOADER = yaml.SafeLoader
yaml.load("{}", SAFE_LOADER)
