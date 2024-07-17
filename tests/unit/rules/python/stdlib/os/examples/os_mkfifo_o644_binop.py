# level: NONE
import os
from stat import *
import sys


fifo_path = "my_pipe"
os.mkfifo(fifo_path, mode=S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

if os.fork() == 0:
    with open(fifo_path, "w") as fifo:
        fifo.write("Hello from the child process!\n")
    sys.exit(0)

with open(fifo_path, "r") as fifo:
    print("Parent process reads:", fifo.read())

os.remove(fifo_path)
