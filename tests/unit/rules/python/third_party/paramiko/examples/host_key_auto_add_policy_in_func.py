from paramiko import client


def init_ssh_client(ssh):
    ssh.set_missing_host_key_policy(client.AutoAddPolicy)


ssh_client = client.SSHClient()
init_ssh_client(ssh_client)
