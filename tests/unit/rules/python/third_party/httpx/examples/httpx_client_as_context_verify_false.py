import httpx


with httpx.Client(verify=False) as client:
    response = client.get("https://localhost")
