import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.get("http://python.org", ssl=False) as response:
        print(await response.text())
