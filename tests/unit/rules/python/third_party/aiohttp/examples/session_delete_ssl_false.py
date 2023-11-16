# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 55
# end_column: 60
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.delete("http://python.org", ssl=False) as response:
        print(await response.text())
