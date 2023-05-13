import httpx


client = httpx.AsyncClient(verify=False)
response = client.get("https://localhost")
