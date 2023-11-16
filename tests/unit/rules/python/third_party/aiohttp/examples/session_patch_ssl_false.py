# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 54
# end_column: 59
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.patch("http://python.org", ssl=False) as response:
        print(await response.text())
