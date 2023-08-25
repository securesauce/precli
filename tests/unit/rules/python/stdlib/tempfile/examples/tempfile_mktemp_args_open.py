import tempfile


filename = tempfile.mktemp("", "tmp", dir=None)
f = open(filename, "w+")
f.write(b"Hello World!\n")
f.close()
