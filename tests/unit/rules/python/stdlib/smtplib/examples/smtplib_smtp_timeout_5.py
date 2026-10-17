# level: NONE
import smtplib
import ssl


server = smtplib.SMTP("smtp.example.com", 587, timeout=5)
server.starttls(context=ssl.create_default_context())
