from fastapi import BackgroundTasks
import smtplib
from email.mime.text import MIMEText

def send_email_otp(to_email: str, otp: str):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "rohan22am@gmail.com"
    smtp_password = "riml tzxo iccp hxqo"

    msg = MIMEText(f"Your OTP for password reset is: {otp}")
    msg['Subject'] = "Password Reset OTP"
    msg['From'] = smtp_username
    msg['To'] = to_email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, to_email, msg.as_string())