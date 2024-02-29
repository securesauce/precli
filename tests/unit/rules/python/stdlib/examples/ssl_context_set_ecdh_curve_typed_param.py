# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 27
# end_column: 39
import ssl


def set_curve(context: ssl.SSLContext) -> None:
    context.set_ecdh_curve("prime192v1")


context = ssl.SSLContext()
set_curve(context)
