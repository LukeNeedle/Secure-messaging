from flask import Flask, redirect, url_for, render_template, request
from flask_login import LoginManager, login_user, logout_user, login_required
from models import User
import sqlite3

app = Flask(__name__)
app.secret_key = 'super-secret-string'

login_manager = LoginManager()
login_manager.init_app(app)

def entry_cleaner(entry, mode):
    """
    Remove unwanted characters from a string.
    mode = "sql" --> Removes characters that could be used for sql injection
    mode = "password" --> Removes characters that could be used for sql injection as well as characters that aren't on the english keyboard.

    Args:
        entry (string): The input that needs cleaning
        mode (string): Selects how the entry should be cleaned.

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
        return entry_cleaner(entry, "sql").encode("ascii", "ignore").decode()

@login_manager.user_loader
def user_loader(email):
    """
    Generates the user object from the email address provided.

    Args:
        email (string): The email to lookup.

    Returns:
        User: The user object if the user exists, otherwise it returns None
    """
    
    cleanedEmail = entry_cleaner(entry=email, mode="sql")

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(f"""SELECT * FROM Staff WHERE StaffID='{cleanedEmail}';""")
    result = cursor.fetchone()
    if result == None:
        connection.close()
        return None
    
    userDetails = {
        "id": result[0],
        "firstName": result[1],
        "lastName": result[2],
        "title": result[3],
        "email": result[4],
        "accountEnabled": result[5],
        "accountArchived": result[6],
        "passHash": result[7],
        "passSalt": result[8],
        "SENCo": result[9],
        "safeguarding": result[10],
        "admin": result[11]
    }
    connection.close()
    return User(userDetails)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cleanedEmail = entry_cleaner(email, "sql")
        cleanedPassword = entry_cleaner(password, "password")

        if cleanedEmail != email:
            # Invalid email
            return redirect(url_for('login'))
        
        if cleanedPassword != password:
            # Invalid password
            return redirect(url_for('login'))
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        
        cursor.execute(f"""SELECT passHash FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return redirect(url_for('login'))
        
        if result[0] == cleanedPassword:
            cursor.execute(f"""SELECT * FROM Staff WHERE Email='{cleanedEmail}';""")
            result = cursor.fetchone()
            if result == None:
                connection.close()
                return None
            else:
                userDetails = {
                    "id": result[0],
                    "title": result[1],
                    "firstName": result[2],
                    "lastName": result[3],
                    "email": result[4],
                    "accountEnabled": result[5],
                    "accountArchived": result[6],
                    "passHash": result[7],
                    "passSalt": result[8],
                    "SENCo": result[9],
                    "safeguarding": result[10],
                    "admin": result[11]
                }
                user = User(userDetails)
                login_user(user, remember=True)
        connection.close()
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')