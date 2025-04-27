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
    # This is the status of the application. I need to make error alerts in the program.
    # Add missing values to respective status updates
    error = False
    if error:
        app_status = "Error"
    else:
        app_status = 'Running'
    print(f"App Status: {app_status}")

    # This will get the alarms from the alarm database and display it in the web gui
    conn = sqlite3.connect('/alarms.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alarms')
    alarms = cursor.fetchmany(10)
    cursor.close

    return render_template('dashboard.html', status=app_status, alarms=alarms)

@app.route('/update_ip', methods=['POST'])
#This will handle the submission of a new IP in the form.
def update_ip():
    ip_address = request.form.get('ipaddress')
    # Creating an ip database
    conn = sqlite3.connect('/ip_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS station(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ipaddress TEXT NOT NULL,)''')
    conn.commit()
    cursor.execute('INSERT INTO station (ipaddress) VALUES (?)', (ip_address))
    conn.commit()

    cursor.execute('SELECT * FROM station')
    ipaddress = cursor.fetchone()
    cursor.close()

    if not ipaddress:
        ipaddress='Missing Value'
    else:
        return ipaddress

    #This will send the IP address value back to the html file
    return render_template('/dashboard.html', ip_address=ipaddress)

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

    if not user_list:
        user_list = ['Missing Values']
    else:
        return user_list
    return render_template('/dashboard.html', user=user_list)

@app.route('/removeuser', methods=['POST'])
def remove_user():
    remove_name = request.form.get('removename')
    remove_number = request.form.get('removenumber')
    conn = sqlite3.connect('./user_database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE name = ? AND phone = ?', (remove_name, remove_number))
    conn.commit()
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
    
    if not alarm_class_list:
        alarm_class_list=['Missing Value']
    else:
        return alarm_class_list
    return render_template(alarm_class_list)

@app.route('/timedelay', methods=['POST'])
def time_delay():
    delay=request.form.get('timedelay')
    delay = int(delay) if delay and delay.isdigit() else 0
    if delay > 0:
        delay = delay
    else:
        delay = 24
        
    conn = sqlite3.connect('delay.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_delay(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delay TEXT NOT NULL)''')
    conn.commit()

    cursor.execute('INSERT INTO time_delay(delay) VALUES (?)', (delay))
    conn.commit()
    cursor.close()


@app.route('/logout', methods=['POST'])
def logout():
    # This might not work since it's started in login.py
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/reboot', methods=['GET'])
def reboot():
    subprocess.Popen(['usr/bin/docker', 'restart', 'alarmcast'])

@app.route('/stationname', methods=['POST'])
def station_name():
    name = request.form.get('/stationname')
    conn = sqlite3.connect('/station_name.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS station_name(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL)''')
    conn.commit()
    cursor.execute('INSERT INTO station_name(name) VALUE (?)', (name))
    conn.commit()
    cursor.close()

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

    connection = sqlite3.connect('/ip_database.db')
    ip_cursor = connection.cursor()
    ip_cursor.execute('SELECT * FROM station')
    ip_address = ip_cursor.fetchone()
    ip_cursor.close()

    alarm_names = []

    for alarm_class in classes:
        bql_query = f"""
        bql:select parent.name as Name, parent.parent.name as Parent_Name, parent.out.value as Value
        from baja:Component where alarmClass = {alarm_class}"""

        encoded_query = urllib.parse.quote(bql_query)
        
        api_url = f'https://{ip_address}:443/dgdb?db=bql&query={encoded_query}'

        username = os.getenv('API_USER')
        password = os.getenv('API_PASSWORD')

        # I'm not sure this updates properly
        alarm_names = alarm_list(get_alarms(api_url, username, password))
        return alarm_names

# This will send an alarm when it's a new alarm.  If it not a new alarm it will send on the chosen time delay.
def send_alarm_messages():
    # This creates an alarm database to compare the alarms pulled from N4 to the previous alarms.
    alarm_names = alarms()
    conn = sqlite3.connect('/alarms.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alarms(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm TEXT NOT NULL)''')
    conn.commit()

    cursor.execute('INSERT INTO alarms(alarm) VALUES (?)', (alarm_names))
    conn.commit()

    cursor.execute('SELECT * FROM alarms')
    alarm_table = cursor.fetchone()
    cursor.close()

    # This pulls the user database to send the messages to that user.
    connection = sqlite3.connect('/user_database.db')
    user_cursor = connection.cursor()
    user_cursor.execute('SELECT * FROM users')
    users = user_cursor.fetchall()
    user_cursor.close()

    # This pulls latest time delay value from the time delay database

    delay_conn = sqlite3.connect('/delay.db')
    delay_cursor = delay_conn.cursor()
    delay_cursor.execute('SELECT * FROM time_delay')
    delay = delay_cursor.fetchone()
    delay_cursor.close()

    station_conn = sqlite3.connect('/station_name.db')
    station_cursor = station_conn.cursor()
    station_cursor.execute('SELECT * FROM station_name')
    station_name = station_cursor.fetchall()
    station_cursor.close()

    phone_numbers = []
    for user in users:
        phone_numbers.append(user[-1])
        return phone_numbers

    # This will check for new alarms compared to previous alarms and sends them to each user. 
    for alarm in alarm_names:
        if alarm not in alarm_table:
            for number in phone_numbers:
                alarm_messages(alarm, station_name=station_name, number=number)

    # Make sure to add for existing alarms
    for alarm in alarm_names:
        if alarm in alarm_names:
            time_delay = delay * 60 * 60
            time.sleep(time_delay)
            for number in phone_numbers:
                alarm_messages(alarm, station_name='Add This', number=number)

def background_tasks():

    ip_conn = sqlite3.connect('/ip_database.db')
    ip_cursor = ip_conn.cursor()
    ip_cursor.execute('SELECT * FROM station')
    ip = ip_cursor.fetchone()
    ip_cursor.close()

    user_conn = sqlite3.connect('/user_database.db')
    user_cursor = user_conn.cursor()
    user_cursor.execute('SELECT * FROM users')
    users = user_cursor.fetchone()
    user_cursor.close()

    alarm_class_conn = sqlite3.connect('/alarm_class_database.db')
    alarm_class_cursor = alarm_class_conn.cursor()
    alarm_class_cursor.execute('SELECT * FROM class')
    alarm_class = alarm_class_cursor.fetchone()
    alarm_class_cursor.close()

    station_name_conn = sqlite3.connect('/station_name.db')
    station_name_cursor = station_name_conn.cursor()
    station_name_cursor.execute('SELECT * FROM station_name')
    station_name = station_name_cursor.fetchone()
    station_name_cursor.close()

    if ip and users and alarm_class and station_name:
        while True:
            send_alarm_messages()

# This checks to make sure there is a database before starting the script.
def check_databases():
    try:
        ip_conn = sqlite3.connect('/ip_database.db')
        ip_cursor = ip_conn.cursor()
        ip_cursor.execute('SELECT * FROM station')
        if ip_cursor.fetchone() is None:
            return False
        
        user_conn = sqlite3.connect('/user_database.db')
        user_cursor = user_conn.cursor()
        user_cursor.execute('SELECT * FROM users')
        if user_cursor.fetchone() is None:
            return False
        
        conn = sqlite3.connect('alarm_class_database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM class')
        if cursor.fetchone() is None:
            return False
        
        conn = sqlite3.connect('station_name.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM station_name')
        if cursor.fetchone() is None:
            return False
        
        return True
    except Exception as e:
        return False
    
if check_databases():
    background_tasks()
        
if __name__ == '__main__':
    
    app.run('0.0.0.0', debug=True)