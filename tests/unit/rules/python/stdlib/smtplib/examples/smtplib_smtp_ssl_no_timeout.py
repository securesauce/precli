# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 25
# end_column: 88
import smtplib
import ssl


server = smtplib.SMTP_SSL("smtp.example.com", 587, context=ssl.create_default_context())
