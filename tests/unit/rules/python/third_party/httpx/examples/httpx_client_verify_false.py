import httpx


client = httpx.Client(verify=False)
response = client.get("https://localhost")
