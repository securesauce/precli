# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 0
# end_column: 10
import dill


pick = dill.dumps({"a": "b", "c": "d"})
dill.loads(pick)
