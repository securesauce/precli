import requests


session = requests.Session()
session.get("https://localhost", verify=False)
