from flask import Flask, redirect, url_for, render_template, request, send_file
from flask_login import LoginManager, login_user, logout_user, login_required
from models import User
import sqlite3

app = Flask(__name__)
app.secret_key = 'super secret string'

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(email):
    # Load user from the database based on the email
    # Replace this with your own logic

    user = User(email)
    return user

@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute(f"""SELECT * FROM Staff WHERE ;""")
    # Load user from the database based on the email
    # Replace this with your own logic
    user = User(email)
    return user

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/style.css')
def stylecss():
    return send_file('templates//style.css')

@app.route('/index.css')
def indexcss():
    return send_file('templates//index.css')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    # Validate the email and password
    # Replace this with your own validation logic

    # Authenticate the user
    user = User(email)
    login_user(user, remember=True)
    return redirect(url_for('main.profile'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'

@app.route('/profile')
@login_required
def profile():
    # Only logged-in users can access this route
    return 'Profile Page'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')