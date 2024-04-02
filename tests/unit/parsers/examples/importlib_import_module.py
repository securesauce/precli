import importlib


query = "worker:run"
module_name, _, func_name = query.partition(":")
module = importlib.import_module(module_name, package="base_package")
