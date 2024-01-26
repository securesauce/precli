# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 5
# end_column: 16
import shelve


filename = "db.dat"
db = shelve.open(filename)
flag = "key" in db
db.close()
