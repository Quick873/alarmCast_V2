from flask_login import LoginManager, UserMixin, login_user
from flask import Flask, request, redirect, url_for, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
# from werkzeug.urls import url_has_allowed_host_and_scheme

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Login')

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

user = User()


# This is used to reload the user object from the user ID
@login_manager.user_loader
def load_user(user_id):
    return user.get(user_id)


#This will run the function when someone goes to the login URL
# @app.route('/login) is the indication to run the function when someone enters the login url
# methods=['GET', 'POST'] means this route handles both get and post request.
# GET - displays the login form.
# POST - Processes the form (validates credentials)
@app.route('/login.html', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # If the credentials are correct.
    if form.validate_on_submit():
        # Login and validate user.
        login_user(user)

        app.flash('Login Successful!')

        # Directs to the next url
        next = app.request.args.get('next')

        # If the url is not valid
        # if not url_has_allowed_host_and_scheme(next, request.host):
        #    return app.abort(400)

        # This directs you to next if next = 'dashboard'.  Otherwise it redirects to 'index'
        return redirect(next or url_for('index'))

    # This renders the login html template and passes the form into that object.
    return render_template('/login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)