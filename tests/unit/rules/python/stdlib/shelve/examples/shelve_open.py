import shelve


filename = "db.dat"
db = shelve.open(filename)
flag = "key" in db
db.close()
