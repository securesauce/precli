# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 61
# end_column: 66
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.patch(
        "http://python.org", verify_ssl=False
    ) as response:
        print(await response.text())
