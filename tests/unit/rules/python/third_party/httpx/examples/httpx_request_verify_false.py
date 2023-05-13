import httpx


httpx.stream("GET", "https://localhost", verify=False)
