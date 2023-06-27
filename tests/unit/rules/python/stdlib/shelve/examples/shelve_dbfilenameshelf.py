import shelve


filename = "db.dat"
db = shelve.DbfilenameShelf(filename)
flag = "key" in db
db.close()
