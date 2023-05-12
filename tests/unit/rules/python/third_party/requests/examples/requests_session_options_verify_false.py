import requests


session = requests.Session()
session.options("https://localhost", verify=False)
