# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 5
# end_column: 16
import shelve


with shelve.open("db.dat") as db:
    flag = "key" in db
