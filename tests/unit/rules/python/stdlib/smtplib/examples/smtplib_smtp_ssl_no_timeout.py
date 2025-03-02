# level: WARNING
# start_line: 10
# end_line: 12
# start_column: 25
# end_column: 1
import smtplib
import ssl


server = smtplib.SMTP_SSL(
    "smtp.example.com", 587, context=ssl.create_default_context()
)
