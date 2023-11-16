# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 62
# end_column: 67
import aiohttp


async with aiohttp.ClientSession() as session:
    async with session.delete(
        "http://python.org", verify_ssl=False
    ) as response:
        print(await response.text())
