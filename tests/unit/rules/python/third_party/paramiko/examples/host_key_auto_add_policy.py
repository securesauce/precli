from paramiko import client

ssh_client = client.SSHClient()


def test_func(ssh):
    ssh.set_missing_host_key_policy(client.AutoAddPolicy)


test_func(ssh)
