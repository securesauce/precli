# level: NONE
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.get("http://python.org", ssl=True) as response:
        print(await response.text())
