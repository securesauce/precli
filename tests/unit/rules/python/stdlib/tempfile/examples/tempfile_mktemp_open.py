import tempfile


filename = tempfile.mktemp()
f = open(filename, "w+")
f.write(b"Hello World!\n")
f.close()
