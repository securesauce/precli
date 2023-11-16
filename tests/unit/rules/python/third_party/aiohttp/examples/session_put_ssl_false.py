# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 52
# end_column: 57
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.put("http://python.org", ssl=False) as response:
        print(await response.text())
