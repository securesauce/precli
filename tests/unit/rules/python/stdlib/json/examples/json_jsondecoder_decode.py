import json


decoder = json.JSONDecoder()
decoder.decode('["foo", {"bar":["baz", null, 1.0, 2]}]')
