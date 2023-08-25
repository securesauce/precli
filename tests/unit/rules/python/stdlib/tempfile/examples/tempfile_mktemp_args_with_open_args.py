import tempfile


filename = tempfile.mktemp("", "tmp", dir=None)
with open(
    filename, "w+", buffering=-1, encoding=None, errors=None, newline=None
) as f:
    f.write(b"Hello World!\n")
