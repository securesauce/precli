# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 21
# end_column: 46
import smtplib
import ssl


server = smtplib.SMTP("smtp.example.com", 587)
server.starttls(context=ssl.create_default_context())
