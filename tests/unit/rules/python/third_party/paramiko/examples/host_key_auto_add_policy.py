# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 46
# end_column: 59
from paramiko import client


ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
