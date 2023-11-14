# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 50
# end_column: 63
from paramiko import client


if (ssh_client := client.SSHClient()) is not None:
    ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
