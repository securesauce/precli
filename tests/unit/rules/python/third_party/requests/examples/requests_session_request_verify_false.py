import requests


session = requests.Session()
session.request("GET", "https://localhost", verify=False)
