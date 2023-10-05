from flask import Flask, redirect, url_for, render_template, request, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User
import sqlite3
import hash_function

app = Flask(__name__)
app.secret_key = r"1/6,I'#`}n5]>ueon&H_zAAvfB%QQS>y?QwURVhF.WuPL+[<f@JC|olJ>0&X{'R5@eIyN(G~aplodH3qChmU0%A&,p2xugLP%d5VTXoR7^la4ypRA:=#xh~T7IWt,t\\%"

login_manager = LoginManager()
login_manager.init_app(app)


#########################################################################
#########################################################################
####################             Logic              #####################
#########################################################################
#########################################################################


def entry_cleaner(entry, mode="sql"):
    """
    Remove unwanted characters from a string.
    mode = "sql" --> Removes characters that could be used for sql injection
    mode = "password" --> Removes characters that could be used for sql injection and characters that could be used for sql injection as well as characters that aren't on the english keyboard.

    Args:
        entry (string): The input that needs cleaning
        mode (string, optional): Selects how the entry should be cleaned. Defaults to "sql".

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
        cleanedEntry = entry_cleaner(entry, "sql")

        cleanedEntry = cleanedEntry.encode("ascii", "ignore").decode()

        return cleanedEntry
    else:
        raise f"Invalid mode: {mode} for entryCleaner"

def hashing(variable, salt:str = None, mode:str="password"):
    """
    Hashes the variable/file passed in.

    Args:
        variable (string): The variable/file that needs cleaning
        salt (string, optional): The salt to be applied to the variable/file.
        mode (string, optional): Selects how the variable/file should be hashed. Defaults to "password".

    Returns:
        string: The hashed variable/file
    """
    if mode == "password":
        result = hash_function.hash_variable(variable, salt)
    elif mode == "file":
        result = hash_function.hash_file(variable)
    return result


#########################################################################
#########################################################################
####################           User Tools           #####################
#########################################################################
#########################################################################


@login_manager.user_loader
def user_loader(email):
    """
    Generates the user object from the email address provided.

    Args:
        email (string): The 

    Returns:
        User: The user object
    """

    cleanedEmail = entry_cleaner(entry=email, mode="sql")

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(f"""SELECT * FROM Staff WHERE Email='{cleanedEmail}';""")
    result = cursor.fetchone()
    if result == None:
        cursor.execute(f"""SELECT * FROM Staff WHERE StaffID='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            return None
    
    userDetails = {
        "id": result[0],
        "title": result[1],
        "firstName": result[2],
        "lastName": result[3],
        "email": result[4],
        "accountEnabled": result[5],
        "accountArchived": result[6],
        "password": result[7],
        "passhash": result[8],
        "SENCo": result[9],
        "safeguarding": result[10],
        "admin": result[11]
    }
    user = User(userDetails['id'], userDetails['title'], userDetails['firstName'], userDetails['lastName'], userDetails['accountEnabled'], userDetails['accountArchived'], userDetails['password'], userDetails['passhash'], userDetails['SENCo'], userDetails['safeguarding'], userDetails['admin'])
    connection.close()
    return user


#########################################################################
#########################################################################
####################           Endpoints            #####################
#########################################################################
#########################################################################


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if type(current_user._get_current_object()) is User:
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html")
    
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        cleanedEmail = entry_cleaner(email)
        cleanedPassword = entry_cleaner(password)

        print(cleanedPassword)
        print(password)
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
        
        if result[0] == hashing(cleanedPassword, "password"):
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
                    "password": result[7],
                    "passhash": result[8],
                    "SENCo": result[9],
                    "safeguarding": result[10],
                    "admin": result[11]
                }
                user = User(userDetails['id'], userDetails['title'], userDetails['firstName'], userDetails['lastName'], userDetails['accountEnabled'], userDetails['accountArchived'], userDetails['password'], userDetails['passhash'], userDetails['SENCo'], userDetails['safeguarding'], userDetails['admin'])
                login_user(user, remember=True)
        connection.close()
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if type(current_user._get_current_object()) is User:
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#########################################################################
#########################################################################
####################              CSS               #####################
#########################################################################
#########################################################################


@app.route('/static/css/base.css')
def base_css():
    return send_file('templates//base.css')


#########################################################################
#########################################################################
####################             Launch             #####################
#########################################################################
#########################################################################


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')