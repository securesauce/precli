# level: ERROR
# start_line: 14
# end_line: 14
# start_column: 5
# end_column: 21
import getpass
import telnetlib


HOST = "localhost"
user = input("Enter your remote account: ")
password = getpass.getpass()

with telnetlib.Telnet(HOST) as tn:
    tn.read_until(b"login: ")
    tn.write(user.encode("ascii") + b"\n")
    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode("ascii") + b"\n")

    tn.write(b"ls\n")
    tn.write(b"exit\n")

    print(tn.read_all().decode("ascii"))
