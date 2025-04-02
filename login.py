from flask_login import LoginManager, UserMixin
from flask import Flask

app = Flask(__name__)

# I am not 100% sure what this does. 
app.secret_key = "Redbe@rd@5510"

# Login Manager lets the application and Flask Login work together.
login_manager = LoginManager()

# I am not sure what this does yet. 
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


#This should route to the login page.
@app.route('/login', methods=['GET', 'POST'])
