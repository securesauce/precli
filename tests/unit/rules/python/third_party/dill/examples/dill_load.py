# level: WARNING
# start_line: 14
# end_line: 14
# start_column: 0
# end_column: 9
import io

import dill


file_obj = io.BytesIO()
dill.dump([1, 2, "3"], file_obj)
file_obj.seek(0)
dill.load(file_obj)
