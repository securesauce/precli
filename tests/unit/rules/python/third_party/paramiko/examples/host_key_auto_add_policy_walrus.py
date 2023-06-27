from paramiko import client


if (ssh_client := client.SSHClient()) is not None:
    ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
