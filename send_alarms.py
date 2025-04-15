import threading
import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

account_sid = os.getenv("TWILIO_ACCOUNT_SID")
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
client = Client(account_sid, auth_token)




def alarm_messages(names, station_name, number):
    for name in names:
        message = client.messages.create(
            body=f"{name} is in Alarm! {station_name}",
            from_="+15157052770",
            to=f"+1{number}"
        )
        