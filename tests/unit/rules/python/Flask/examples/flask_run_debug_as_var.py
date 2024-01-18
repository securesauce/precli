# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 14
# end_column: 19
from flask import Flask


app = Flask(__name__)
debug = True
app.run(debug=debug)
