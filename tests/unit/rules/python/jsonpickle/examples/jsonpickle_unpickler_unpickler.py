# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 0
# end_column: 30
import jsonpickle


pick = jsonpickle.encode({"a": "b", "c": "d"})
jsonpickle.unpickler.Unpickler().restore(pick)
