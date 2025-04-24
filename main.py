from flask import Flask, request, render_template, session, redirect, url_for
import requests
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore
from alarmCast import get_alarms
from send_alarms import alarm_messages, alarm_list
import threading
import time
from dotenv import load_dotenv
import os
import sqlite3
import subprocess

load_dotenv()

# This creates the flask app
app = Flask(__name__)

@app.route("/")
def index():
    error = False
    if error:
        app_status = "Error"
    else:
        app_status = 'Running'
    print(f"App Status: {app_status}")
    return render_template('dashboard.html', status=app_status)

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
    # This creates the database to store user data.
    conn = sqlite3.connect('./user_database.db')
    # Next step is to create the table
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL)''')
    
    conn.commit()
    # Add values to the table
    cursor.execute('INSERT INTO users (name,phone) VALUES (?,?)', (addname, addnumber))
    conn.commit()

    # Pull values from table
    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    user_list = []
    for row in rows:
        user_list.append(row)
        return user_list
    conn.close()
    return render_template('/dashboard.html', user=user_list)

@app.route('/removeuser', methods=['POST'])
def remove_user():
    remove_name = request.form.get('removename')
    remove_number = request.form.get('removenumber')
    conn = sqlite3.connect('./user_database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE name = ? AND phone = ?', (remove_name, remove_number))
    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    user_list = []
    for row in rows:
        user_list.append(row)
        return user_list
    conn.close()
    return render_template('./dashboard.html', user=user_list)

@app.route('/alarmclass', methods=['POST'])
def get_alarm_class():
    alarm_class_list = []
    alarm_class = request.form.get('alarm-class')
    conn = sqlite3.connect('/alarm_class_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS class(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarmClass TEXT NOT NULL)''')
    conn.commit()

    conn.execute('INSERT INTO class(alarmClass) VALUES (?)', (alarm_class))
    conn.commit()

    conn.execute('SELECT * FROM class')
    rows = cursor.fetchall()
    for row in rows:
        alarm_class_list.append(row)
        return alarm_class_list
    return render_template(alarm_class_list)

@app.route('/timedelay', methods=['POST'])
def time_delay():
    delay=request.form.get('timedelay')
    delay = int(delay) if delay and delay.isdigit() else 0
    return delay if delay > 0 else 24

@app.route('/logout', methods=['POST'])
def logout():
    # This might not work since it's started in login.py
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/reboot', methods=['GET'])
def reboot():
    subprocess.Popen(['usr/bin/docker', 'restart', 'alarmcast'])



# Start by pulling alarm values. 
def get_alarms(api_url, username, password):
    response = requests.get(api_url, auth=(username, password), verify=False)
    data=response.json
    return data

# This will get the alarms from each alarm class and store them in a list. 
def alarms():
    conn = sqlite3.connect('/alarm_class_database.db')   
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM class')
    classes = cursor.fetchall()
    cursor.close()

    alarm_names = []

    for alarm_class in classes:
        bql_query = f"""
        bql:select parent.name as Name, parent.parent.name as Parent_Name, parent.out.value as Value
        from baja:Component where alarmClass = {alarm_class}"""

        encoded_query = urllib.parse.quote(bql_query)
        
        api_url = f'https://{ipaddress}:443/dgdb?db=bql&query={encoded_query}'

        username = os.getenv('API_USER')
        password = os.getenv('API_PASSWORD')

        alarm_names = alarm_list(get_alarms(api_url, username, password))
        return alarm_names

# This will send an alarm when it's a new alarm.  If it not a new alarm it will send on the chosen time delay.




if __name__ == '__main__':
    
    app.run('0.0.0.0', debug=True)