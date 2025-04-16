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

@app.route('/update_ip', methods=['POST'])
#This will handle the submission of a new IP in the form.
def update_ip():
    ip_address = request.form.get('ipaddress')
    #This will send the IP address value back to the html file
    return render_template('/dashboard.html', ip_address=ip_address)

@app.route('/adduser', methods=['POST'])
# This function assigns the values from the add user form and stores them as a variable.
def adduser():
    addname = request.form.get('addname')
    addnumber = request.form.get('addnumber')
    # There needs to be a SQL lite database created to store the users here.

bql_query = f"""
bql:select parent.name as Name, parent.parent.name as Parent_Name, parent.out.value as Value
from baja:Component where alarmClass = {alarm_class}"""