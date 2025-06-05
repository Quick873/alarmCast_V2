from flask import Flask, request, render_template, session, redirect, url_for, flash
import requests
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore
from alarmCast import get_alarms
from send_alarms import alarm_messages, alarm_list
import threading
import traceback
from dotenv import load_dotenv
import os
import sqlite3
import subprocess
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from datetime import timedelta, datetime
import time
# from werkzeug.urls import url_has_allowed_host_and_scheme

load_dotenv()

# This creates the flask app
app = Flask(__name__)

app_status = "Starting"

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')

# This is used to validate browser cookies and to make sure they weren't tampered with. 
app.secret_key = "Redbe@rd@5510"

# Login Manager lets the application and Flask Login work together.
login_manager = LoginManager()

# This registers Flask Login functionality with the app. 
login_manager.init_app(app)
login_manager.login_view = 'login'

# This will need to be more secure than this.
Users = {
    "AdminWCC" : {"password" : "Redbe@rd@5510"}
}

# User Class
# UserMixin - This is to provide default implementations of is_active(), is_authenticated(), get_id(), is_anonymous()
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# This is used to reload the user object from the user ID
@login_manager.user_loader
def load_user(user_id):
    if user_id in Users:
       return User(user_id)
    return None 


#This will run the function when someone goes to the login URL
# @app.route('/login) is the indication to run the function when someone enters the login url
# methods=['GET', 'POST'] means this route handles both get and post request.
# GET - displays the login form.
# POST - Processes the form (validates credentials)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # If the credentials are correct.
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # Login and validate user.
        if username in Users and Users[username]['password'] == password:
            user = User(username)
            login_user(user)
            session.permanent = True
            flash('Login Successful!')

        # Directs to the next url
            next = request.args.get('next')

        # If the url is not valid
        # if not url_has_allowed_host_and_scheme(next, request.host):
        #    return app.abort(400)

        # This directs you to next if next = 'dashboard'.  Otherwise it redirects to 'index'
            return redirect(next or url_for('index'))
        flash('Incorrect username or password.')
    # This renders the login html template and passes the form into that object.
    return render_template('login.html', form=form)


@app.route("/")
@login_required
def index():
    #if 'user' not in session:
    #    return redirect(url_for('login'))
    # This is the status of the application. I need to make error alerts in the program.
    # Add missing values to respective status updates
    global app_status
    print(f"App Status: {app_status}")

    # This will get the alarms from the alarm database and display it in the web gui
    while True:
            try:
                conn = sqlite3.connect('alarms.db')
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM alarms')
                alarms = cursor.fetchmany(10)
                cursor.close()

                if not alarms:
                    alarms = 'No Alarms.'
            except Exception as e:
                conn = sqlite3.connect('alarms.db')
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS errors(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        error TEXT NOT NULL)''')
                conn.commit()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (e))
                conn.commit()
                cursor.close()
                print('Error:', e)
                alarms = 'Error bringing up alarm database.'

            try:
                user_conn = sqlite3.connect('user_database.db')
                user_cursor = user_conn.cursor()
                user_cursor.execute('SELECT * FROM users')
                users = user_cursor.fetchall()
                user_cursor.close()
            # Pull values from table
                user_list = [row for row in users]

                if not user_list:
                    user_list = 'Missing Values'
            except Exception as e:
                conn = sqlite3.connect('error.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (e))
                conn.commit()
                cursor.close()
                print('Error:', e)
                user_list = 'Error bringing up user database.'

            try:
                ip_conn = sqlite3.connect('ip_database.db')
                ip_cursor = ip_conn.cursor()
                ip_cursor.execute('SELECT * FROM station')
                ip_address = ip_cursor.fetchone()
                ip_cursor.close()

                ip_address = ip_address[1]

                if not ip_address:
                    ip_address='Missing Value'

            except Exception as e:
                conn = sqlite3.connect('error.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (e))
                conn.commit()
                cursor.close()
                print('Error:', e)
                ip_address = 'Error bringing up IP database.'

            try:
                alarm_class_list = []
                alarm_class_conn = sqlite3.connect('alarm_class_database.db')
                alarm_class_cursor = alarm_class_conn.cursor()
                alarm_class_cursor.execute('SELECT * FROM class')
                alarm_class = alarm_class_cursor.fetchall()
                alarm_class_cursor.close()
                for row in alarm_class:
                    class_name = row[-1]
                    if class_name not in alarm_class_list:
                        alarm_class_list.append(class_name)
                        print(alarm_class_list)
                    
    
                if not alarm_class_list:
                    alarm_class_list=['Missing Value']
                
            except Exception as e:
                conn = sqlite3.connect('error.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (e))
                conn.commit()
                cursor.close()
                print('Error:', e)
                alarm_class_list = ['Error bringing up alarm class database.']

            try:
                error_conn = sqlite3.connect('error.db')
                error_cursor = error_conn.cursor()
                error_cursor.execute('SELECT * FROM errors')
                errors = error_cursor.fetchmany(5)
                error_cursor.close()

                if not errors:
                    errors = 'No Errors'
            except Exception as e:
                error_conn = sqlite3.connect('error.db')
                error_cursor = error_conn.cursor()
                error_cursor.execute('INSERT INTO errors (error) VALUES (?)', (e))
                error_conn.commit()
                error_cursor.close()
                print('Error:', e)
                errors = 'Error bringing up error database.'    

            return render_template('dashboard.html', status=app_status, alarms=alarms, users=user_list, ip_address=ip_address, alarm_class=alarm_class_list, errors=errors)
            
@app.route('/update_ip', methods=['POST'])
#This will handle the submission of a new IP in the form.
def update_ip():
    ip_address = request.form.get('ipaddress')
    # Creating an ip database
    conn = sqlite3.connect('ip_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS station(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ipaddress TEXT NOT NULL)''')
    conn.commit()
    cursor.execute('INSERT INTO station (ipaddress) VALUES (?)', (ip_address,))
    conn.commit()
    cursor.close()
    #This will send the IP address value back to the html file
    return redirect(url_for('index'))

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
    if addname and addnumber:
        cursor.execute('INSERT INTO users (name,phone) VALUES (?,?)', (addname, addnumber))
        conn.commit()
    conn.close()
    
    return redirect(url_for('index'))

@app.route('/removeuser', methods=['POST'])
def remove_user():
    remove_name = request.form.get('removename')
    remove_number = request.form.get('removenumber')
    conn = sqlite3.connect('./user_database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE name = ? AND phone = ?', (remove_name, remove_number))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/alarmclass', methods=['POST'])
def get_alarm_class():
    alarm_class = request.form.get('alarm-class')
    conn = sqlite3.connect('alarm_class_database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS class(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarmClass TEXT NOT NULL)''')
    conn.commit()

    conn.execute('INSERT INTO class(alarmClass) VALUES (?)', (alarm_class,))
    conn.commit()

    
    
    return redirect(url_for('index'))

@app.route('/timedelay', methods=['POST'])
def time_delay():
    delay=request.form.get('time-delay')
    if not delay or not delay.isdigit():
        delay = '10'
    delay = f'{delay}:00'
        
    conn = sqlite3.connect('delay.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS time_delay(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delay TEXT NOT NULL)''')
    conn.commit()

    cursor.execute('INSERT INTO time_delay(delay) VALUES (?)', (delay,))
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
    name = request.form.get('station-name')
    conn = sqlite3.connect('station_name.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS station_name(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL)''')
    conn.commit()
    cursor.execute('INSERT INTO station_name(name) VALUES (?)', (name,))
    conn.commit()
    cursor.close()
    return redirect(url_for('index'))

# Start by pulling alarm values. 
def get_alarms(api_url, username, password):
    print(api_url)
    try:
        response = requests.get(api_url, auth=(username, password), verify=False)
        print(response.status_code)
        print(response.text.strip())
        if response.status_code == 200 and response.text.strip():
            try:
                data=response.json()
                print('getting alarms')
                return data
            except Exception as e:
                conn = sqlite3.connect('error.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (str(e),))
                conn.commit()
                cursor.close()
                print('Error:', e)
                return {}
        
        else:
            print('error connecting to station')
            return {}
    except Exception as e:
        print('Error connecting to station', str(e))

# This will get the alarms from each alarm class and store them in a list. 
def alarms():
    conn = sqlite3.connect('alarm_class_database.db')   
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM class')
    classes = cursor.fetchall()
    cursor.close()

    connection = sqlite3.connect('ip_database.db')
    ip_cursor = connection.cursor()
    ip_cursor.execute('SELECT * FROM station')
    ip_address = ip_cursor.fetchone()
    ip_cursor.close()
    ip_address = ip_address[1]

    alarm_names = []
    alarm_class_list = []

    for row in classes:
        class_name = row[1]
        if class_name not in alarm_class_list:
            alarm_class_list.append(class_name)

    for alarm_class in alarm_class_list:
        bql_query = f"""
        bql:select parent.name as 'Name', parent.parent.parent.name as 'Parent_Name', parent.out.value as 'Value'
        from baja:Component where alarmClass = '{alarm_class}'"""

        encoded_query = urllib.parse.quote(bql_query)
        
        api_url = f'https://{ip_address}:443/dgdb?db=bql&query={encoded_query}'

        username = os.getenv('API_USER')
        password = os.getenv('API_PASSWORD')

        # I'm not sure this updates properly
        alarm_names = alarm_list(get_alarms(api_url, username, password))
        print('looking for alarms')
    return alarm_names

# This will send an alarm when it's a new alarm.  If it not a new alarm it will send on the chosen time delay.
def send_alarm_messages():
    # This creates an alarm database to compare the alarms pulled from N4 to the previous alarms.
    alarm_names = alarms()
    print(alarm_names)
    print(type(alarm_names))
    now = datetime.now()
    now_str = now.isoformat()
    current_time = now.strftime('%H:%M')
    print(current_time)
    conn = sqlite3.connect('alarms.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alarms(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm TEXT NOT NULL,
            active_since TEXT NOT NULL,
            is_active INTEGER DEFAULT 1)''')
    conn.commit()
    cursor.execute('SELECT alarm, active_since, is_active FROM alarms')
    rows = cursor.fetchall()
    print(rows)
    # Check if this is being done correctly.
    alarm_table = {row[0]: row for row in rows}
    print(alarm_table)
    for alarm in alarm_names:
        alarm_key = f'{alarm[0]}_{alarm[1]}'
        print(alarm)
        print(alarm_key)
        if alarm_key not in alarm_table:
            print('New Alarm')
            cursor.execute('INSERT INTO alarms(alarm, active_since, is_active) VALUES (?, ?, ?)', (alarm_key, now.isoformat(), 1))
            conn.commit()

        if alarm_key in alarm_table and alarm_table[alarm_key][2] == 0:
            print('Alarm not awknowledged.')
            cursor.execute('UPDATE alarms SET active_since = ?, is_active = 1 WHERE alarm = ?', (now.isoformat(), 1, alarm))
            conn.commit()

    for row in alarm_table:
        alarm_keys = {f'{a[0]}_{a[1]}' for a in alarm_names}
        print(row)
        print(alarm_names)
        if row not in alarm_keys and alarm_table[alarm_key][2] == 1:
            print('alarm awknowledged.')
            cursor.execute('UPDATE alarms SET is_active = 0 WHERE alarm = ?', (0, alarm))
            conn.commit()
    
    cursor.close()
    
    # This pulls the user database to send the messages to that user.
    connection = sqlite3.connect('user_database.db')
    user_cursor = connection.cursor()
    user_cursor.execute('SELECT * FROM users')
    users = user_cursor.fetchall()
    user_cursor.close()
    print('stopping after user database.')
    # This pulls latest time delay value from the time delay database
    delay = '10:00'
    try:
        delay_conn = sqlite3.connect('delay.db')
        delay_cursor = delay_conn.cursor()
        delay_cursor.execute('SELECT * FROM time_delay')
        row = delay_cursor.fetchone()
        delay_cursor.close()
        if row:
            delay = row[1]

        print('Delay:', delay)
    except Exception as e:
        error_conn = sqlite3.connect('error.db')
        error_cursor = error_conn.cursor()
        error_cursor.execute('INSERT INTO errors (error) VALUES (?)', (str(e),))
        error_conn.commit()
        error_cursor.close()
        print('Error:', e)
    print('stopping after delay database.', delay)
    station_conn = sqlite3.connect('station_name.db')
    station_cursor = station_conn.cursor()
    station_cursor.execute('SELECT * FROM station_name')
    station_name = station_cursor.fetchone()
    station_cursor.close()
    station_name = station_name[-1]
    phone_numbers = []

    for user in users:
        phone_numbers.append(user[-1])

    print('stopping after phone number loop')

    # This will check for new alarms compared to pre
    # vious alarms and sends them to each user. 
    for alarm in alarm_names:
        print(alarm_names)
        print(alarm_key)
        print(station_name)
        alarm_key = f'{alarm[0]}_{alarm[1]}'
        print('starting for loop')
        if alarm_key not in alarm_table or (alarm_key in alarm_table and alarm_table[alarm_key][2] == 1 and alarm_table[alarm_key][1] == now_str):
            print('new alarm message')
            for number in phone_numbers:
                print("message sent")
                alarm_messages(alarm_key, station_name=station_name, number=number)

    # Make sure to add for existing alarms
    for alarm in alarm_names:
        alarm_key = f'{alarm[0]}_{alarm[1]}'
        if alarm_key in alarm_table and current_time == delay and alarm_table[alarm_key][2] == 1:
            print("Current Time is", current_time)
            for number in phone_numbers:
                alarm_messages(alarm_key, station_name=station_name, number=number)
                print('Message sent!')
                time.sleep(60)

def background_tasks():

    global app_status
    while True:
        try:
            send_alarm_messages()
            app_status = "Running"
            print(app_status)
        except Exception as e:
            error_conn = sqlite3.connect('error.db')
            error_cursor = error_conn.cursor()
            error_cursor.execute('INSERT INTO errors (error) VALUES (?)', (str(e),))
            error_conn.commit()
            error_cursor.close()
            error = f'Send Alarm Error: {str(e)}\n{traceback.format_exc()}'
            print(error)
            # Build an error database
            try:
                conn = sqlite3.connect('error.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO errors (error) VALUES (?)', (error,))
                conn.commit()
                cursor.close()
                conn.close()
                app_status = "Error"
                print(app_status)
            except Exception as db_error:
                conn
                print(f"error {db_error}")
        time.sleep(1)

# This checks to make sure there is a database before starting the script.
def check_databases():
    try:
        ip_conn = sqlite3.connect('ip_database.db')
        ip_cursor = ip_conn.cursor()
        ip_cursor.execute('SELECT * FROM station')
        if ip_cursor.fetchone() is None:
            return False
        
        user_conn = sqlite3.connect('user_database.db')
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
        error_conn = sqlite3.connect('error.db')
        error_cursor = error_conn.cursor()
        error_cursor.execute('INSERT INTO errors (error) VALUES (?)', (str(e),))
        error_conn.commit()
        error_cursor.close()
        print('Error:', e)
        return False
   
if check_databases():
    app_status = "Running"
else:
    app_status = "Error"
print(app_status)


        
if __name__ == '__main__':
    thread = threading.Thread(target=background_tasks, daemon=True)
    thread.start()
    
    app.run('0.0.0.0', debug=True)