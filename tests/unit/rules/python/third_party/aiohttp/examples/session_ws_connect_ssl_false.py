# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 59
# end_column: 64
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.ws_connect("http://python.org", ssl=False) as response:
        print(await response.text())
