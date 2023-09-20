from flask import Flask, redirect, url_for, render_template, request
from flask_login import LoginManager, login_user, logout_user, login_required
from models import User
import sqlite3

app = Flask(__name__)
app.secret_key = 'super secret string'

login_manager = LoginManager()
login_manager.init_app(app)

def entryCleaner(entry, mode="sql"):
    """
    Remove unwanted characters from a string.
    mode = "sql" --> Removes characters that could be used for sql injection
    mode = "password" --> Removes characters that could be used for sql injection and characters that could be used for sql injection as well as characters that aren't on the english keyboard.

    Args:
    entry: The input that needs cleaning
    mode: Selects how the entry should be cleaned

    Returns:
    string: The cleaned string
    """

    if mode == "sql":
        allowedChars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '-', '.', '/', ':', '<', '>', '?', '@', '[', ']', '^',
                        '_', '`', '|', '~']
        cleanedEntry = ""
        
        for letter in entry:
            if letter in allowedChars:
                cleanedEntry += letter

        return cleanedEntry
    elif mode == "password":
        cleanedEntry = entryCleaner(entry, "sql")

        cleanedEntry = cleanedEntry.encode("ascii", "ignore").decode()

        return cleanedEntry
    else:
        raise f"Invalid mode: {mode} for entryCleaner"

@login_manager.user_loader
def user_loader(email):
    # Load user from the database based on the email
    # Replace this with your own logic

    user = User(email)
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('name')
    cleanedUsername = entryCleaner(username, "sql")
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute(f"""SELECT * FROM Staff WHERE ;""")
    result = cursor.fetchone()
    if result == None:
        raise "User not found"
    else:

        (1, 'John', 'Smith', 'Mr', 'JS@school.uk', 'False', 'False', 'Averysecurepasswordthathasbeenhashed', 'Arandomstringofcharacters', 'True', 'False', 'False')
    userDetails = {
        "id": result[0],
        "title": result[1],
        "firstName": result[2],
        "lastName": result[3],
        "email": result[4]
        "accountEnabled": result[5],
        "accountArchived": result[6],
        "password": result[7],
        "passhash": result[8],
        "SENCo": result[9],
        "safeguarding": result[10],
        "admin": result[11]
    }

    # Load user from the database based on the email
    # Replace this with your own logic
    user = User()
    return user

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

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