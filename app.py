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
import json
from datetime import datetime
import uuid

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
    mode = "message" --> Removes characters that could be used for sql injection but has support for multiple lines. 

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
        raise ValueError(f"Invalid mode: {mode} for entryCleaner")

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

def save_message_attachments(senderID, attachments, timeStamp, messageID):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    if not os.path.exists(f"uploads/{senderID}"):
        os.mkdir(f"uploads/{senderID}")
    if not os.path.exists(f"uploads/{senderID}/{timeStamp}"):
        os.mkdir(f"uploads/{senderID}/{timeStamp}")
    for file in attachments:
        filePath = f"uploads/{senderID}/{timeStamp}/{file.filename}"
        cursor.execute(f"""INSERT INTO Files(OwnerID, Origin, FilePath, TimeStamp)
                       VALUES (?, ?, ?, ?);
                       """, (senderID, f'M+{messageID}', filePath, timeStamp))
        connection.commit()
        file.save(filePath)
    return connection


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
        if type(current_user._get_current_object()) is not User:
            print("User not logged in")
            return render_template("login.html")
        return redirect(url_for('dashboard'))
    
    elif request.method == 'POST':
        if type(current_user._get_current_object()) is User:
            print("User already logged in")
            return redirect(url_for('dashboard'))
        email = request.form.get('email')
        password = request.form.get('password')

        #Email validation
        cleanedEmail = entry_cleaner(email, "email")
        if cleanedEmail != email.lower():
            print("Invalid email")
            return redirect(url_for('login'))
        del email
        
        #Password Validation
        cleanedPassword = entry_cleaner(password, "password")
        if cleanedPassword != password:
            print("Invalid password")
            return redirect(url_for('login'))
        del password

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        
        cursor.execute(f"""SELECT passHash FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("User not found")
            return redirect(url_for('login'))
        else:
            passHash = result[0]
        
        cursor.execute(f"""SELECT PassSalt FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("User not found")
            return redirect(url_for('login'))
        else:
            salt = result[0]
        
        if passHash != hashing(cleanedPassword, salt):
            connection.close()
            print("Password doesn't match stored password")
            return redirect(url_for('login'))
        
        cursor.execute(f"""SELECT * FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        connection.close()
        if result == None:
            print("User not found")
            return redirect(url_for('login'))
        
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

        login_user(User(userDetails), remember=False)
        print("Successfully logged in")
        return redirect(url_for('login'))
# Objective 2 completed

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if type(current_user._get_current_object()) is not User:
        print("User not logged in")
        return redirect(url_for('login'))
    return render_template("dashboard.html")

@app.route('/messages', methods=['GET'])
@login_required
def messages():
    if type(current_user._get_current_object()) is not User:
        print("User not logged in")
        return redirect(url_for('login'))
    return render_template("messaging.html")

@app.route('/messages/inbox', methods=['GET'])
@login_required
def messages_inbox():
    if type(current_user._get_current_object()) is not User:
        print("User not logged in")
        return redirect(url_for('login'))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(f"""SELECT * FROM Messages WHERE RecipientID='{current_user.id}' and Archived='False';""")
    result = cursor.fetchall()
    if result == None or len(result) == 0:
        return render_template("inbox.html", msg="empty")
    else:
        messages = result

    response = [] # A list of messages

    for message in messages:
        tempResponse = [message[1]] # 0 = Message ID, 1 = Sender email, 2 = timestamp as a readable time in a list, 3 = Url, 4 = First 10 characters of message
        
        # Example message
        #(4, 2, 2, '\x02\x1c', '1699959519.800139', 'False', 'False', 'BiW')
        #messageID, senderID, recipientID, message, URL, timestamp, readreciepts, archived, key
        
        cursor.execute(f"""SELECT Email FROM Staff WHERE StaffID='{message[1]}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("Recipient not found")
            return redirect(url_for('messages'))
        else:
            tempResponse.append(result[0])
        
        timestamp = datetime.fromtimestamp(float(message[5]))
        tempResponse.append(
            f"{timestamp.strftime('%a')} {timestamp.strftime('%d')} {timestamp.strftime('%b')} {timestamp.strftime('%y')} at {timestamp.strftime('%I')}:{timestamp.strftime('%M')}{timestamp.strftime('%p').lower()}"
            )
        
        cursor.execute(f"""SELECT HashedUrl FROM Messages WHERE MessageID='{message[0]}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("URL not found")
            return redirect(url_for('messages'))
        else:
            tempResponse.append(result[0])
        
        with open("secrets.json", "r") as f:
            key = encryption.substitution_decrypt(encryptedText=message[8], key=json.load(f)['MessageKey'])
        
        mail = str(
            encryption.decrypt(
                cipherText=message[3].replace("<Double_Quote>", "\"").replace("<Single_Quote>", "\'").replace("<Escape>", "\\").replace("<New_Line>", "\n").replace("<Tab>", "\t").replace("<Carriage_Return>", "\r").replace("<Null_Character>", "\0").replace("<ASCII_Bell>", "\a").replace("<ASCII_Backspace>", "\b").replace("<ASCII_Form_Feed>", "\f").replace("<ASCII_Vertical_Tab>", "\v"),
                vernamKey=str(key[:-2]),
                subsitutionKey=int(key[-2:])
                )
            ).strip().replace("\n", ' ').replace("\0", '').replace("\a", '')
        
        if len(mail) > 30:
            tempResponse.append(mail[:30])
        elif len(mail) <= 30:
            tempResponse.append(mail.ljust(30).replace(" ", "&nbsp;"))
        
        response.append(tempResponse)
    
    connection.close()
    return render_template("inbox.html", mail=response)
    # return render_template("under_construction.html")

@app.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def messages_compose():
    if type(current_user._get_current_object()) is not User:
        print("User not logged in")
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        return render_template("compose.html")
    elif request.method == 'POST':
        currentUser = current_user.get_user_dictionary()
        recipient = request.form.get('recipient')
        message = request.form.get('message')
        readReceipts = request.form.get('read-receipts')
        attachments = request.files.getlist('attachments')
        
        #Email validation
        cleanedEmail = entry_cleaner(recipient, "email")
        if cleanedEmail != recipient.lower():
            print("Invalid email")
            return redirect(url_for('messages_compose'))
        del recipient
        
        if readReceipts == "True":
            readReceipts = True
        else:
            readReceipts = False

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute(f"""SELECT StaffID FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            print("Invalid email")
            connection.close()
            return redirect(url_for('messages_compose'))
        else:
            recipientID = result[0]

        timeStamp = float(datetime.timestamp(datetime.now()))
        
        vernamKey = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(message)))
        subsitutionKey = random.randint(1, 61)

        cleanedMessage = message.replace('\0', '')
        
        encryptedMessage = encryption.encrypt(cleanedMessage, vernamKey=vernamKey, subsitutionKey=subsitutionKey)
        if subsitutionKey < 10:
            subsitutionKey = "0" + str(subsitutionKey)
        with open("secrets.json", "r") as f:
            key = encryption.substitution_encrypt(plainText=(vernamKey + str(subsitutionKey)), key=json.load(f)['MessageKey'])
        
        cleanedEncryptedMessage = ""
        for character in encryptedMessage:
            if character == '"':
                cleanedEncryptedMessage += "<Double_Quote>"
            elif character == "'":
                cleanedEncryptedMessage += "<Single_Quote>"
            elif character == "\\":
                cleanedEncryptedMessage += "<Escape>"
            elif character == "\n":
                cleanedEncryptedMessage += "<New_Line>"
            elif character == "\t":
                cleanedEncryptedMessage += "<Tab>"
            elif character == "\r":
                cleanedEncryptedMessage += "<Carriage_Return>"
            elif character == "\0":
                cleanedEncryptedMessage += "<Null_Character>"
            elif character == "\a":
                cleanedEncryptedMessage += "<ASCII_Bell>"
            elif character == "\b":
                cleanedEncryptedMessage += "<ASCII_Backspace>"
            elif character == "\f":
                cleanedEncryptedMessage += "<ASCII_Form_Feed>"
            elif character == "\v":
                cleanedEncryptedMessage += "<ASCII_Vertical_Tab>"
            else:
                cleanedEncryptedMessage += character
        
        cursor.execute("""INSERT INTO Messages(SenderID, RecipientID, Message, HashedUrl, TimeStamp, ReadReceipts, Archived, Key)
                        VALUES (?, ?, ?, ?, ?, ?, 'False', ?);
                        """, (currentUser["id"], recipientID, cleanedEncryptedMessage, str(uuid.uuid4()), timeStamp, str(readReceipts), key))
        connection.commit()
        try:
            pass
        except sqlite3.IntegrityError:
            print("Failed CHECK constraint")
            return redirect(url_for('messages_compose'))
        
        cursor.execute(f"""SELECT MessageID FROM Messages
                        WHERE SenderID=? and RecipientID=? and Message=? and TimeStamp=? and ReadReceipts=? and Key=?;
                        """, (currentUser["id"], recipientID, cleanedEncryptedMessage, timeStamp, str(readReceipts), key))
        result = cursor.fetchone()

        if result == None:
            connection.close()
            print("Failed to save message")
            return redirect(url_for('messages_compose'))
        else:
            messageID = result[0]
        
        with open("secrets.json", "r") as f:
            cursor.execute(f"""UPDATE Messages SET HashedUrl = ? WHERE MessageID = ?;
                            """, (encryption.substitution_encrypt(
                                plainText=str(uuid.uuid5(uuid.NAMESPACE_URL, str(messageID))),
                                key=json.load(f)['UrlKey']),
                                messageID
                                ))
            connection.commit()
            
        
        connection.close()
        if attachments[0].filename != '':
            connection = save_message_attachments(currentUser['id'], attachments, timeStamp, messageID)
        connection.close()
        return redirect(url_for('messages_compose'))

@app.route('/messages/inbox/<string:encryptedMessageID>')
@login_required
def preview_message(encryptedMessageID):
    if type(current_user._get_current_object()) is not User:
        return redirect(url_for('login'))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute(f"""SELECT MessageID FROM Messages WHERE HashedUrl='{encryptedMessageID}';""")
    result = cursor.fetchone()
    if result == None:
        print("URL not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    else:
        messageID = result[0]
    
    cursor.execute(f"""SELECT * FROM Messages WHERE MessageID='{messageID}';""")
    result = cursor.fetchone()
    if result == None:
        print("Message not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    else:
        messageID = result[0]
    
    connection.close()

@app.route('/reports', methods=['GET'])
@login_required
def reporting():# TODO
    if type(current_user._get_current_object()) is not User:
        return redirect(url_for('login'))
    return render_template("under_construction.html")

@app.route('/settings', methods=['GET', 'POST'])
@login_required
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
            print("Invalid email")
            return render_template("user_settings.html", msg="Invalid Email", entry=["email"])
        del email
        
        #Password Validation
        cleanedOldPassword = entry_cleaner(oldPassword, "password")
        cleanedNewPassword = entry_cleaner(newPassword, "password")
        cleanedConfirmNewPassword = entry_cleaner(confirmNewPassword, "password")
        if cleanedOldPassword != oldPassword:
            print("Invalid old password")
            return render_template("user_settings.html", msg="Old password contains illegal characters", entry=["old-password"])
        if cleanedNewPassword != newPassword:
            print("Invalid new password")
            return render_template("user_settings.html", msg="New password contains illegal characters", entry=["new-password"])
        if cleanedConfirmNewPassword != confirmNewPassword:
            print("Invalid confirm new password")
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
            print("User not found")
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        elif result[0].lower() != cleanedEmail.lower():
            connection.close()
            print("Invalid email")
            return render_template("user_settings.html", msg="Your email contains illegal characters", entry=["email"])
        
        # Getting user's password
        cursor.execute(f"""SELECT passHash FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("User not found")
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        else:
            passHash = result[0]
        
        cursor.execute(f"""SELECT passSalt FROM Staff WHERE Email='{cleanedEmail}';""")
        result = cursor.fetchone()
        if result == None:
            connection.close()
            print("User not found")
            return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"])
        else:
            salt = result[0]
        
        if passHash != hashing(cleanedOldPassword, salt):
            connection.close()
            print("Old password isn't valid")
            return render_template("user_settings.html", msg="Your old password doesn't match the password that you entered", entry=["old-password"])
        
        if cleanedNewPassword != cleanedConfirmNewPassword:
            connection.close()
            print("New password and confirm new password aren't the same")
            return render_template("user_settings.html", msg="Please use the same new password when confirming your new password", entry=["new-password", "confirm-new-password"])
        
        cursor.execute(f"""UPDATE Staff SET PassHash = '{hashing(cleanedNewPassword, salt)}' WHERE StaffID = '{current_user.id}';""")
        result = cursor.fetchone()

        userDetails = current_user.get_user_dictionary()
        userDetails["passhash"] = hashing(cleanedNewPassword, salt)
        logout_user()
        login_user(User(userDetails), remember=False)
        return render_template("user_settings.html", msg="Password changed successfully", entry=["submit"])

@app.route('/app/users', methods=['GET'])
@login_required
def manage_user():# TODO
    if type(current_user._get_current_object()) is not User:
        return redirect(url_for('login'))
    return render_template("under_construction.html")

@app.route('/app/settings', methods=['GET'])
@login_required
def app_settings():# TODO
    if type(current_user._get_current_object()) is not User:
        return redirect(url_for('login'))
    return render_template("under_construction.html")

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

@app.route('/static/css/messaging.css')
def messaging_css():
    return send_file('static//css//messaging.css')

@app.route('/static/css/messaging_inbox.css')
def messaging_inbox_css():
    return send_file('static//css//messaging_inbox.css')

@app.route('/static/css/messaging_compose.css')
def messaging_compose_css():
    return send_file('static//css//messaging_compose.css')

@app.route('/static/css/user_settings.css')
def user_settings_css():
    return send_file('static//css//user_settings.css')
    
@app.route('/static/css/under_construction.css')
def under_construction_css():
    return send_file('static//css//under_construction.css')

@app.route('/static/css/404.css')
def four_zero_four_css():
    return send_file('static//css//404.css')


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