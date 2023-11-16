# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 53
# end_column: 58
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.post("http://python.org", ssl=False) as response:
        print(await response.text())
