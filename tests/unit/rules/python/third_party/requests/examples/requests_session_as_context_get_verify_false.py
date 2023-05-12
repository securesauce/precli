import requests


with requests.Session() as session:
    session.get("https://localhost", verify=False)
