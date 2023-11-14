# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 54
# end_column: 67
from paramiko import client


client.SSHClient().set_missing_host_key_policy(client.AutoAddPolicy)
