import requests


session = requests.Session()
session.patch("https://localhost", verify=False)
