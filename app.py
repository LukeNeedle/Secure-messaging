from flask import Flask, redirect, url_for, render_template, request, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User
import sqlite3
import hash_function
import re as regex
import os

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
    elif mode == "email":
        cleanedEntry = entry_cleaner(entry, "sql").lower()
        if not regex.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', cleanedEntry):
            return None
        else:
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
        cleanedEmail = entry_cleaner(email)
        if cleanedEmail != email.lower():
            # Invalid email
            return redirect(url_for('login'))
        del email
        
        #Password Validation
        cleanedPassword = entry_cleaner(password)
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
        
        if passHash == hashing(cleanedPassword, salt, "password"):
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


@app.route('/dashboard')
def dashboard():
    if type(current_user._get_current_object()) is User:
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))

@app.route('/messages')
def messages():
    if type(current_user._get_current_object()) is User:
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))

@app.route('/reports')
def reporting():
    if type(current_user._get_current_object()) is User:
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))

@app.route('/settings')
def user_settings():
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
    return send_file('static//css//base.css')

@app.route('/static/css/login.css')
def login_css():
    return send_file('static//css//login.css')

@app.route('/static/css/dashboard.css')
def dashboard_css():
    return send_file('static//css//dashboard.css')


#########################################################################
#########################################################################
####################             Images             #####################
#########################################################################
#########################################################################


#                                                        #
# This function is no longer in use after commit 275306d #
#                                                        #
#
# @app.route('/static/icon/<image_name>')
# def images(image_name: str):
#     """
#     Send the requested image file if it exists, otherwise send a placeholder image.

#     Args:
#     image_name: The name of the requested image file.

#     Returns:
#     Send file: The requested image file if it exists, otherwise the placeholder image file.
#     """
#     if image_name+".svg" in os.listdir("static//icons"):
#         return send_file(f"static//icons//{image_name}.svg")
#     else:
#         return send_file(f"static//icons//place_holder.png")


#########################################################################
#########################################################################
####################             Errors             #####################
#########################################################################
#########################################################################


def handle_not_found(error):
    return redirect(url_for('login'))


#########################################################################
#########################################################################
####################             Launch             #####################
#########################################################################
#########################################################################


if __name__ == '__main__':
    app.register_error_handler(404, handle_not_found)
    app.run(debug=True, host='0.0.0.0')