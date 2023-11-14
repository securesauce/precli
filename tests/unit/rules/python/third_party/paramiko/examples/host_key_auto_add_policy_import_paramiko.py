# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 48
# end_column: 61
import paramiko


ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
