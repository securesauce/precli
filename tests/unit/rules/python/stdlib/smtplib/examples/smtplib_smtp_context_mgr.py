# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 9
# end_column: 14
import smtplib


with smtplib.SMTP("domain.org") as smtp:
    smtp.noop()
    smtp.login("user", "password")
