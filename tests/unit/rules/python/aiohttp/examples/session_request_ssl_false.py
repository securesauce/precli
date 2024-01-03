# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 56
# end_column: 61
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.request("http://python.org", ssl=False) as response:
        print(await response.text())
