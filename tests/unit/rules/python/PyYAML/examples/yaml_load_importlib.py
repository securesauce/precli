# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 5
# end_column: 9
import importlib


yaml = importlib.import_module("yaml")
yaml.load("{}")
