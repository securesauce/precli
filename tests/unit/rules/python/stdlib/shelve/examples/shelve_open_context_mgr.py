import shelve


with shelve.open("db.dat") as db:
    flag = "key" in db
