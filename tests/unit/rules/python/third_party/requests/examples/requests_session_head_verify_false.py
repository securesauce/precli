import requests


session = requests.Session()
session.head("https://localhost", verify=False)
