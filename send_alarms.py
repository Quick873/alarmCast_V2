import threading
import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

account_sid = os.getenv("TWILIO_ACCOUNT_SID")
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
client = Client(account_sid, auth_token)

def alarm_list(data):
    name = []
    if data and "rows":
        for row in data["rows"]:
            print('Row:', row)
            if row[-1] == True:
                name.append((row[0], row[1]))
    return name


def alarm_messages(names, station_name, number):
    message = client.messages.create(
        body=f"{names} is in Alarm! {station_name}",
        from_="+15157052770",
        to=f"+1{number}"
        )
        