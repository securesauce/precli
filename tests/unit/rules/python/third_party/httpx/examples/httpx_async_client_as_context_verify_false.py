import httpx


async with httpx.AsyncClient(verify=False) as client:
    response = await client.get("https://localhost")
