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
import sqlite3

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

bql_query = f"""
bql:select parent.name as Name, parent.parent.name as Parent_Name, parent.out.value as Value
from baja:Component where alarmClass = {alarm_class}"""