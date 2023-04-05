import yaml


ystr = yaml.dump({'a': 1, 'b': 2, 'c': 3}, loader=yaml.SafeLoader)

assert True
