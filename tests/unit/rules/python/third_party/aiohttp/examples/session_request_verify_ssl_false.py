# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 63
# end_column: 68
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.request(
        "http://python.org", verify_ssl=False
    ) as response:
        print(await response.text())
