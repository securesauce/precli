# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 9
# end_column: 20
import os
import sys


fifo_path = "my_pipe"
os.mkfifo(fifo_path)

if os.fork() == 0:
    with open(fifo_path, "w") as fifo:
        fifo.write("Hello from the child process!\n")
    sys.exit(0)

with open(fifo_path, "r") as fifo:
    print("Parent process reads:", fifo.read())

os.remove(fifo_path)
