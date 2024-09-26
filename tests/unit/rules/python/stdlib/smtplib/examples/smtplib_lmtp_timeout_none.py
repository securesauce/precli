# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 55
# end_column: 59
import smtplib
import ssl


server = smtplib.LMTP("smtp.example.com", 587, timeout=None)
