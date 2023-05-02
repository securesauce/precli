import yaml

a = {}
a["SAFE_LOADER"] = yaml.SafeLoader
yaml.load("{}", a["SAFE_LOADER"])
