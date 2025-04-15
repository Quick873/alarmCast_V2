from flask import Flask, request, render_template
import requests
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore
from alarmCast import get_alarms
from send_alarms import alarm_messages
import threading
import time
from dotenv import load_dotenv
import os

load_dotenv()

# This creates the flask app
app = Flask(__name__)

@app.route("/")
def index():
    return render_template('dashboard.html')