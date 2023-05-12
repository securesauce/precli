import requests


session = requests.Session()
session.post("https://localhost", verify=False)
