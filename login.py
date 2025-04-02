from flask_login import LoginManager, UserMixin
from flask import Flask

app = Flask(__name__)

# This is used to validate browser cookies and to make sure they weren't tampered with. 
app.secret_key = "Redbe@rd@5510"

# Login Manager lets the application and Flask Login work together.
login_manager = LoginManager()

# This registers Flask Login functionality with the app. 
login_manager.init_app(app)

# This will need to be more secure than this.
Users = {
    "AdminWCC" : {"password" : "Redbe@rd@5510"}
}

# User Class
# UserMixin - This is to provide default implementations of is_active(), is_authenticated(), get_id(), is_anonymous()
class User(UserMixin):
    pass


# This is used to reload the user object from the user ID
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


#This will run the function when someone goes to the login URL
# @app.route('/login) is the indication to run the function when someone enters the login url
# methods=['GET', 'POST'] means this route handles both get and post request.
# GET - displays the login form.
# POST - Processes the form (validates credentials)
@app.route('/login', methods=['GET', 'POST'])
