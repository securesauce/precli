# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 40
# end_column: 45
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.request(
        "http://python.org", verify_ssl=False
    ) as response:
        print(await response.text())
