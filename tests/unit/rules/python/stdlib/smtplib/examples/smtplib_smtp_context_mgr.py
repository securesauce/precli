import smtplib


with smtplib.SMTP("domain.org") as smtp:
    smtp.noop()
    smtp.login("user", "password")
