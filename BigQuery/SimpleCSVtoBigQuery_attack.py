import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Path to the JSON file (in the same folder as this script)
json_filename = "YourJsonFile.json"
json_path = os.path.join(os.path.dirname(__file__), json_filename)

# Read the JSON file
with open(json_path, "r", encoding="utf-8") as f:
    json_content = f.read()

# Email settings
sender_email = "xxx@gmail.com"
receiver_email = "xxx@hanmail.net"
subject = "Sending JSON file content"
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_user = "xxx@gmail.com"
smtp_password = "xxxx xxxx xxxx xxxx"  # App password is recommended

# Create the email message
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject

# Attach the JSON content to the email body
msg.attach(MIMEText(json_content, "plain", "utf-8"))

# Print the email content to the console
print("Email will be sent with the following content:\n")
print("Subject:", subject)
print("From:", sender_email)
print("To:", receiver_email)
print("Body:\n", json_content)

# Send the email
with smtplib.SMTP(smtp_server, smtp_port) as server:
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.send_message(msg)

print("Email sent successfully")