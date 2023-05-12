import requests


session = requests.Session()
session.put("https://localhost", verify=False)
