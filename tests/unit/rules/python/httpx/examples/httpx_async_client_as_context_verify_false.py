# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 36
# end_column: 41
import httpx


async with httpx.AsyncClient(verify=False) as client:
    response = await client.get("https://localhost")
