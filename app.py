# Flask libraries
from flask import Flask, redirect, url_for, render_template, request, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Custom libraries
from models import User
import hash_function
import encryption

# Misc. libraries
import sqlite3
import re as regex
import os
import string
import random

app = Flask(__name__)
app.secret_key = r"1/6,I'#`}n5]>ueon&H_zAAvfB%QQS>y?QwURVhF.WuPL+[<f@JC|olJ>0&X{'R5@eIyN(G~aplodH3qChmU0%A&,p2xugLP%d5VTXoR7^la4ypRA:=#xh~T7IWt,t\\%"

login_manager = LoginManager()
login_manager.init_app(app)


#########################################################################
#########################################################################
####################             Logic              #####################
#########################################################################
#########################################################################


def entry_cleaner(entry, mode):
    """
    Remove unwanted characters from a string.
    mode = "sql" --> Removes characters that could be used for sql injection
    mode = "password" --> Removes characters that could be used for sql injection as well as characters that aren't on the english keyboard.
    mode = "email" --> Removes characters that could be used for sql injection and checks that it is a valid email.

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
        cleanedEntry = entry_cleaner(entry, "sql")

        cleanedEntry = cleanedEntry.encode("ascii", "ignore").decode()

        return cleanedEntry
    elif mode == "email":
        cleanedEntry = entry_cleaner(entry, "sql").lower()
        if not regex.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', cleanedEntry):
            return None
        else:
            return cleanedEntry
    else:
        raise f"Invalid mode: {mode} for entryCleaner"

def hashing(variable:str, salt:str):
    """
    Hashes the variable passed in.

    Args:
        variable (string): The variable that needs cleaning
        salt (string): The salt to be applied to the variable.

    Returns:
        string: The hashed variable
    """
    
    result = hash_function.hash_variable(variable, salt)
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
        email (string): The email to lookup.

    Returns:
        User: The user object if the user exists, otherwise it returns None
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
        "firstName": result[1],
        "lastName": result[2],
        "title": result[3],
        "email": result[4],
        "accountEnabled": result[5],
        "accountArchived": result[6],
        "passhash": result[7],
        "passsalt": result[8],
        "SENCo": result[9],
        "safeguarding": result[10],
        "admin": result[11]
    }
    connection.close()
    return User(userDetails)


#########################################################################
#########################################################################
####################           Endpoints            #####################
#########################################################################
#########################################################################


# Objective 2 started
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

        #Email validation
        cleanedEmail = entry_cleaner(email, "email")
        if cleanedEmail != email.lower():
            # Invalid email
            return redirect(url_for('login'))
        del email
        
        #Password Validation
        cleanedPassword = entry_cleaner(password, "password")
        if cleanedPassword != password:
            # Invalid password
            return redirect(url_for('login'))
        del password

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        
        cursor.execute(f"""SELECT passHash FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return redirect(url_for('login'))
        else:
            passHash = result[0]
        
        cursor.execute(f"""SELECT passSalt FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return redirect(url_for('login'))
        else:
            salt = result[0]
        
        if passHash == hashing(cleanedPassword, salt):
            cursor.execute(f"""SELECT * FROM Staff WHERE Email='{cleanedEmail}';""")
            result = cursor.fetchone()
            if result == None:
                connection.close()
                return None
            else:
                userDetails = {
                    "id": result[0],
                    "firstName": result[1],
                    "lastName": result[2],
                    "title": result[3],
                    "email": result[4],
                    "accountEnabled": result[5],
                    "accountArchived": result[6],
                    "passhash": result[7],
                    "passsalt": result[8],
                    "SENCo": result[9],
                    "safeguarding": result[10],
                    "admin": result[11]
                }

                login_user(User(userDetails), remember=True)
        connection.close()
        return redirect(url_for('login'))
# Objective 2 completed


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if type(current_user._get_current_object()) is User:
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))

@app.route('/messages', methods=['GET'])
def messages():
    if type(current_user._get_current_object()) is User:
        return render_template("under_construction.html")
    else:
        return redirect(url_for('login'))

@app.route('/reports', methods=['GET'])
def reporting():
    if type(current_user._get_current_object()) is User:
        return render_template("under_construction.html")
    else:
        return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
def user_settings():
    if type(current_user._get_current_object()) is not User:
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        return render_template("user_settings.html", msg="", entry=[])
    elif request.method == 'POST':
        email = request.form.get('email')
        oldPassword = request.form.get('old-password')
        newPassword = request.form.get('new-password')
        confirmNewPassword = request.form.get('confirm-new-password')

        #Email validation
        cleanedEmail = entry_cleaner(email, "email")
        if cleanedEmail != email.lower():
            # Invalid email
            return render_template("user_settings.html", msg="Invalid Email", entry=["email"])
        del email
        
        #Password Validation
        cleanedOldPassword = entry_cleaner(oldPassword, "password")
        cleanedNewPassword = entry_cleaner(newPassword, "password")
        cleanedConfirmNewPassword = entry_cleaner(confirmNewPassword, "password")
        if cleanedOldPassword != oldPassword:
            # Invalid password
            return render_template("user_settings.html", msg="Old password contains illegal characters", entry=["old-password"])
        if cleanedNewPassword != newPassword:
            # Invalid password
            return render_template("user_settings.html", msg="New password contains illegal characters", entry=["new-password"])
        if cleanedConfirmNewPassword != confirmNewPassword:
            # Invalid password
            return render_template("user_settings.html", msg="Confirm new password contains illegal characters", entry=["confirm-new-password"])
        del oldPassword
        del newPassword
        del confirmNewPassword

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        # Checking email
        cursor.execute(f"""SELECT Email FROM Staff WHERE StaffID='{current_user.id}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        elif result[0].lower() != cleanedEmail.lower():
            connection.close()
            # Invalid email
            return render_template("user_settings.html", msg="Your email contains illegal characters", entry=["email"])
        
        # Getting user's password
        cursor.execute(f"""SELECT passHash FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        else:
            passHash = result[0]
        
        cursor.execute(f"""SELECT passSalt FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            # User not found
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        else:
            salt = result[0]
        
        if passHash != hashing(cleanedOldPassword, salt):
            connection.close()
            # Old password isn't valid
            return render_template("user_settings.html", msg="Your old password doesn't match the password that you entered", entry=["old-password"])
        
        if cleanedNewPassword != cleanedConfirmNewPassword:
            connection.close()
            # New password and confirm new password aren't the same
            return render_template("user_settings.html", msg="Please use the same new password when confirming your new password", entry=["new-password", "confirm-new-password"])
        
        cursor.execute(f"""UPDATE Staff SET PassHash = '{hashing(cleanedNewPassword, salt)}' WHERE StaffID = '{current_user.id}';""")
        result = cursor.fetchone()

        userDetails = current_user.get_user_dictionary()
        userDetails["passhash"] = hashing(cleanedNewPassword, salt)
        logout_user()
        login_user(User(userDetails), remember=True)
        return render_template("user_settings.html", msg="Password changed successfully", entry=["submit"])

@app.route('/app/users', methods=['GET'])
def manage_user():
    if type(current_user._get_current_object()) is User:
        return render_template("under_construction.html")
    else:
        return redirect(url_for('login'))

@app.route('/app/settings', methods=['GET'])
def app_settings():
    if type(current_user._get_current_object()) is User:
        return render_template("under_construction.html")
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
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
    return send_file('static//css//base.css')

@app.route('/static/css/login.css')
def login_css():
    return send_file('static//css//login.css')

@app.route('/static/css/dashboard.css')
def dashboard_css():
    return send_file('static//css//dashboard.css')

@app.route('/static/css/user_settings.css')
def user_settings_css():
    return send_file('static//css//user_settings.css')
    
@app.route('/static/css/under_construction.css')
def under_construction_css():
    return send_file('static//css//under_construction.css')

@app.route('/static/css/under_construction.css')
def four_zero_four_css():
    return send_file('static//css//under_construction.css')


#########################################################################
#########################################################################
####################             Errors             #####################
#########################################################################
#########################################################################


def handle_not_found(error):
    if type(current_user._get_current_object()) is User:
        return render_template("404.html")
    else:
        return redirect(url_for('login'))


#########################################################################
#########################################################################
####################             Launch             #####################
#########################################################################
#########################################################################


if __name__ == '__main__':
    app.register_error_handler(404, handle_not_found)
    app.run(debug=True, host='0.0.0.0')