from paramiko import client

client.SSHClient().set_missing_host_key_policy(client.WarningPolicy)
