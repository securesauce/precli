import requests


session = requests.Session()
session.delete("https://localhost", verify=False)
