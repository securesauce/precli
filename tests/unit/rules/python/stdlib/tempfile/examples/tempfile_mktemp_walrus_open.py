import tempfile


if filename := tempfile.mktemp():
    with open(filename, "w+") as f:
        f.write(b"Hello World!\n")
