# Flask libraries
from flask import Flask, redirect, url_for, render_template, request, send_file, session, Response
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
from datetime import datetime, timedelta
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


def entry_cleaner(entry:str, mode:str):
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
    """ # Documentation

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
        cleanedEntry = entry_cleaner(entry, "sql") # Recursion

        cleanedEntry = cleanedEntry.encode("ascii", "ignore").decode()

        return cleanedEntry
    elif mode == "email":
        cleanedEntry = entry_cleaner(entry, "sql").lower() # Recursion
        if not regex.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', cleanedEntry):
            return None
        else:
            return cleanedEntry
    else:
        raise ValueError(f"Invalid mode: {mode} for entryCleaner") # Error handling

# Objective 4 started
def save_message_attachments(senderID:int, attachments, timeStamp:float, messageID:int, type:str):
    """
    Saves attachments from a message being sent.

    Args:
        senderID (integer): _description_
        attachments (list of files): _description_
        timeStamp (float): _description_
        messageID (integer): _description_
        type (string): _description_
    """ # Documentation
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    if not os.path.exists(f"uploads/{senderID}"):
        os.mkdir(f"uploads/{senderID}")
    if not os.path.exists(f"uploads/{senderID}/{timeStamp}"):
        os.mkdir(f"uploads/{senderID}/{timeStamp}")
    for file in attachments:
        filePath = f"uploads/{senderID}/{timeStamp}/{file.filename}"
        tempURL = str(uuid.uuid4())
        origin = f"{type[0]}+{messageID}"
        cursor.execute("INSERT INTO Files(OwnerID, Origin, FilePath, HashedUrl, TimeStamp) VALUES (?, ?, ?, ?, ?);"
                       , (
                           senderID,
                           origin,
                           filePath,
                           tempURL,
                           timeStamp
                           )
                       ) # Parameterised SQL
        connection.commit()
        
        cursor.execute("SELECT FileID FROM Files WHERE OwnerID=? and Origin=? and FilePath=? and HashedUrl=? and TimeStamp=?;"
                       , (
                           senderID,
                           origin,
                           filePath,
                           tempURL,
                           timeStamp
                           )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        
        with open("secrets.json", "r") as f: # Reading from files
            cursor.execute("UPDATE Files SET HashedUrl = ? WHERE FileID = ?;"
                           , (encryption.substitution_encrypt(
                               plainText=str(uuid.uuid5(uuid.NAMESPACE_URL, str(messageID))),
                               key=json.load(f)['UrlKey']),
                              str(result)
                              )
                           ) # Parameterised SQL
        connection.commit()
        file.save(filePath) # Writing to files
# Objective 4 completed

# Objective 8 started
def send_read_receipt(data):
    """
    Handles storing read receipts when a message has been read.

    Args:
        data (list): The data from the sent message

    Returns:
        nothing: Returns nothing if there is an error in storing a read receipt
    """ # Documentation
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    with open("secrets.json", "r") as f: # Reading from files
        key = encryption.substitution_decrypt(encryptedText=data[8], key=json.load(f)['MessageKey']) # Decryption
    
    message = f"{current_user.title} {current_user.lname} has read your message:\n"
    message += str(
        encryption.decrypt(
            cipherText=data[3].replace("<Double_Quote>", "\"").replace("<Single_Quote>", "\'").replace("<Escape>", "\\").replace("<New_Line>", "\n").replace("<Tab>", "\t").replace("<Carriage_Return>", "\r").replace("<Null_Character>", "\0").replace("<ASCII_Bell>", "\a").replace("<ASCII_Backspace>", "\b").replace("<ASCII_Form_Feed>", "\f").replace("<ASCII_Vertical_Tab>", "\v"),
            vernamKey=str(key[:-2]),
            subsitutionKey=int(key[-2:])
        ) # Decryption
    ).replace("\0", '').replace("\a", '')
    
    
    timeStamp = float(datetime.timestamp(datetime.now()))
    
    vernamKey = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(message)))
    subsitutionKey = random.randint(1, 61)

    cleanedMessage = message.replace('\0', '')
    
    encryptedMessage = encryption.encrypt(cleanedMessage, vernamKey=vernamKey, subsitutionKey=subsitutionKey) # Encryption
    if subsitutionKey < 10:
        subsitutionKey = "0" + str(subsitutionKey)
    
    with open("secrets.json", "r") as f: # Reading from files
        key = encryption.substitution_encrypt(plainText=(vernamKey + str(subsitutionKey)), key=json.load(f)['MessageKey']) # Encryption
    
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
    
    try:
        cursor.execute("""INSERT INTO Messages(SenderID, RecipientID, Message, HashedUrl, TimeStamp, ReadReceipts, Archived, Key)
                       VALUES (?, ?, ?, ?, ?, 'False', 'False', ?);"""
                       , (
                           data[2],
                           data[1],
                           cleanedEncryptedMessage,
                           str(uuid.uuid4()),
                           timeStamp,
                           key
                           )
                       ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        return
    
    cursor.execute("SELECT MessageID FROM Messages WHERE SenderID=? and RecipientID=? and Message=? and TimeStamp=? and Key=?;"
                   , (
                       data[2],
                       data[1],
                       cleanedEncryptedMessage,
                       timeStamp,
                       key
                       )
                   ) # Parameterised SQL
    result = cursor.fetchone()

    if result == None: # Error Handling
        connection.close()
        print("Failed to save message")
        return
    else:
        messageID = result[0]
    
    with open("secrets.json", "r") as f: # Reading from files
        cursor.execute("UPDATE Messages SET HashedUrl = ? WHERE MessageID = ?;"
                       , (encryption.substitution_encrypt(
                           plainText=str(uuid.uuid5(uuid.NAMESPACE_URL, str(messageID))),
                           key=json.load(f)['UrlKey']), # Encryption
                          messageID
                          )
                       ) # Parameterised SQL
        connection.commit()
    
    cursor.execute("UPDATE Messages SET ReadReceipts='False' WHERE MessageID=?;"
                   , (data[0],)
                   ) # Parameterised SQL
    connection.commit()
    connection.close()
# Objective 8 completed

def check_password_strength(password:str):
    """
    Checks the strength of a password

    Args:
        password (string): The password to be checked

    Returns:
        boolean: If the password strength is valid
    """ # Documentation
    
    if len(password) <= 8:
        return False
    
    digits = 0
    upperCase = 0
    lowerCase = 0
    specialCharacters = 0
    
    for character in password:
        if character in string.digits:
            digits += 1
        elif character in string.ascii_lowercase:
            lowerCase += 1
        elif character in string.ascii_uppercase:
            upperCase += 1
        else:
            specialCharacters += 1
    
    percentageDigits = digits/len(password)
    percentageUpperCase = upperCase/len(password)
    percentageLowerCase = lowerCase/len(password)
    percentageSpecialCharacters = specialCharacters/len(password)
    
    if percentageLowerCase >= 0.8:
        return False
    elif percentageUpperCase >= 0.8:
        return False
    elif percentageDigits >= 0.8:
        return False
    elif percentageSpecialCharacters >= 0.8:
        return False
    
    if percentageLowerCase <= 0.02:
        return False
    elif percentageUpperCase <= 0.02:
        return False
    elif percentageDigits <= 0.02:
        return False
    elif percentageSpecialCharacters <= 0.02:
        return False
    
    for examplePassword in ["password", "changeme"]:
        if examplePassword in password.lower():
            return False
    
    return True

@app.before_request 
def check_for_reset_password():
    if current_user.is_authenticated and request.method == 'GET':
        if len(request.path) < 4:
            pathDot = request.path[0]
        else:
            pathDot = request.path[-4]
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute("SELECT AccountEnabled FROM Staff WHERE StaffID=?;"
                       , (current_user.id,)
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result[0] == "False":
            logout_user()
            return redirect(url_for('login'))
        
        cursor.execute("SELECT PassHash, PassSalt FROM Staff WHERE StaffID=?;"
                       , (current_user.id,)
                       ) # Parameterised SQL
        result = cursor.fetchone()
        connection.close()
        if hash_function.hash_variable("ChangeMe", result[1]) == result[0] and request.path != "/ChangePassword" and pathDot != ".": # Hashing
            print("User needs to change password")
            return redirect(url_for('reset_password'))

# Objective 9 started
@app.before_request
def session_timeout_management():
    """
    This function is called before the endpoint code is run and adds extra time to the session.
    
    The extra time is added as follows:
    - Admin users get 5 minutes added for every request.
    - Safeguarding or senco users get 10 minutes added for every request.
    - Other users get 15 minutes added ofr every request.
    """ # Documentation
    if len(request.path) < 4:
        validPath = request.path[0] != "."
    else:
        validPath = request.path[-4] != "."

    if current_user.is_authenticated and request.method == 'GET' and validPath:
        if current_user.admin:
            extraTime = 5
        elif current_user.safeguarding or current_user.senco:
            extraTime = 10
        else:
            extraTime = 15
        
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=extraTime)
# Objective 9 completed

def generate_data_for_student_link(studentID, staffEmail):
    """
    Generates all of the data needed for student linking, this is a separate function as it needs to run at different points and it is quite long.

    Args:
        cleanedID (string): The student's ID.
        cleanedEmail (string): The staff member's email address.

    Returns:
        error -
        redirect response object: redirect(url_for("staff_student_relationships_lookup"))
        
        no error -
        tuple: studentData, staffDetails, linked, studentID, staffEmail, relationship
    """ # Documentation
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                    , (studentID, )
                    )  # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("Target user not found")
        return redirect(url_for("staff_student_relationships_lookup"))
    
    studentData = [
        f"{result[0]} {result[1]}", #Name
        result[2]                   #DateOfBirth
    ]
    
    cursor.execute("SELECT StaffID, FirstName, LastName, Title, Email FROM Staff WHERE Email=? and AccountArchived='False';"
                    , (staffEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("Target user not found")
        return redirect(url_for("staff_student_relationships_lookup"))
    
    staffDetails = f"{result[3]} {result[1]} {result[2]}: {result[4]}"
    
    cursor.execute("SELECT Relationship FROM StudentRelationship WHERE StudentID = ? AND StaffID = ?;"
                    , (studentID, result[0])
                    ) # Parameterised SQL
    result = cursor.fetchone()
    
    if result == None: # Error Handling
        print("No relationship found")
        relationship = "None"
    else:
        relationship = str(result[0])
    
    connection.close()
    return studentData, staffDetails, studentID, staffEmail, relationship


#########################################################################
#########################################################################
####################           User Tools           #####################
#########################################################################
#########################################################################


@login_manager.user_loader
def user_loader(userID):
    """
    Generates the user object from the email address provided.

    Args:
        userID (string): The email to lookup.

    Returns:
        User: The user object if the user exists, otherwise it returns None
    """ # Documentation

    cleanedUserID = entry_cleaner(entry=userID, mode="sql")

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM Staff WHERE StaffID=?;"
                   , (cleanedUserID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
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
    return User(userDetails) # Dynamic generation of objects


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
            return render_template("login.html", msg="")
        return redirect(url_for('dashboard'))
    
    if type(current_user._get_current_object()) is User:
        print("User already logged in")
        return redirect(url_for('dashboard'))
    
    email = request.form.get('email')
    password = request.form.get('password')

    #Email validation
    cleanedEmail = entry_cleaner(email, "email")
    if cleanedEmail != email.lower(): # Error Handling
        print("Invalid email")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=email)
    del email
    
    #Password Validation
    cleanedPassword = entry_cleaner(password, "password")
    if cleanedPassword != password: # Error Handling
        print("Invalid password")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=cleanedEmail)
    del password

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT passHash FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=cleanedEmail)
    else:
        passHash = result[0]
    
    cursor.execute("SELECT PassSalt FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=cleanedEmail)
    else:
        salt = result[0]
    
    if passHash != hash_function.hash_variable(cleanedPassword, salt): # Hashing and Error Handling
        connection.close()
        print("Password doesn't match stored password")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=cleanedEmail)
    
    cursor.execute("SELECT * FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    connection.close()
    if result == None: # Error Handling
        print("User not found")
        return render_template("login.html", msg="Invalid Credentials", savedEmail=cleanedEmail)
    
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

    login_user(User(userDetails), remember=False) # Dynamic generation of objects
    print("Successfully logged in")
    return redirect(url_for('dashboard'))
# Objective 2 completed

@app.route('/ChangePassword', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'GET':
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute("SELECT PassHash, PassSalt FROM Staff WHERE StaffID=?;"
                       ,(current_user.id, )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        connection.close()
        if hash_function.hash_variable("ChangeMe", result[1]) == result[0]: # Hashing
            print("User needs to change password")
            return render_template("change_reset_password.html", msg="")
        else:
            return redirect(url_for('dashboard'))
    
    newPassword = request.form.get('new-password')
    confirmNewPassword = request.form.get('confirm-new-password')
    
    #Password Validation
    cleanedNewPassword = entry_cleaner(newPassword, "password")
    cleanedConfirmNewPassword = entry_cleaner(confirmNewPassword, "password")
    if cleanedNewPassword != newPassword: # Error Handling
        print("Invalid new password")
        return render_template("change_reset_password.html", msg="New password contains illegal characters", entry=["new-password"])
    if cleanedConfirmNewPassword != confirmNewPassword: # Error Handling
        print("Invalid confirm new password")
        return render_template("change_reset_password.html", msg="Confirm new password contains illegal characters", entry=["confirm-new-password"])
    del newPassword
    del confirmNewPassword

    if not check_password_strength(cleanedNewPassword):
        print("Insecure password")
        return render_template("change_reset_password.html", msg="Insecure password", entry=["new-password","confirm-new-password"])
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    # Getting user's password salt  
    cursor.execute("SELECT passSalt FROM Staff WHERE StaffID=?;"
                   , (current_user.id, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("change_reset_password.html", msg="Server Error")
    else:
        salt = result[0]
    
    if cleanedNewPassword != cleanedConfirmNewPassword:
        connection.close()
        print("New password and confirm new password aren't the same")
        return render_template("change_reset_password.html", msg="Please use the same new password when confirming your new password", entry=["new-password", "confirm-new-password"])
    
    cursor.execute("UPDATE Staff SET PassHash = ? WHERE StaffID=?;"
                   , (hash_function.hash_variable(
                       cleanedNewPassword,
                       salt),
                      current_user.id
                      ) # Hashing
                   ) # Parameterised SQL
    connection.commit()
    
    userDetails = current_user.get_user_dictionary()
    userDetails["passhash"] = hash_function.hash_variable(cleanedNewPassword, salt) # Hashing
    logout_user()
    login_user(User(userDetails), remember=False) # Dynamic generation of objects
    print("Changed Password")
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/messages', methods=['GET'])
@login_required
def messages():
    return render_template("messaging.html")

@app.route('/messages/inbox', methods=['GET'])
@login_required
def messages_inbox():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM Messages WHERE RecipientID=? and Archived='False';"
                   , (current_user.id, )
                   ) # Parameterised SQL
    result = cursor.fetchall()
    if result == None or len(result) == 0:
        return render_template("inbox.html", msg="empty")
    else:
        messages = result

    response = [] # A list of messages

    for message in messages:
        tempResponse = [message[1]]
        
        cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                       , (message[1], )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Recipient not found")
            return redirect(url_for('messages'))
        else:
            tempResponse.append(result[0])
        
        timestamp = datetime.fromtimestamp(float(message[5]))
        tempResponse.append(
            f"{timestamp.strftime('%a')} {timestamp.strftime('%d')} {timestamp.strftime('%b')} {timestamp.strftime('%y')} at {timestamp.strftime('%I')}:{timestamp.strftime('%M')}{timestamp.strftime('%p').lower()}"
            )
        
        cursor.execute("SELECT HashedUrl FROM Messages WHERE MessageID=?;"
                       , (message[0], )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("URL not found")
            return redirect(url_for('messages'))
        else:
            tempResponse.append(result[0])
        
        with open("secrets.json", "r") as f:
            key = encryption.substitution_decrypt(encryptedText=message[8], key=json.load(f)['MessageKey']) # Decryption

        mail = str(
            encryption.decrypt(
                cipherText=message[3].replace("<Double_Quote>", "\"").replace("<Single_Quote>", "\'").replace("<Escape>", "\\").replace("<New_Line>", "\n").replace("<Tab>", "\t").replace("<Carriage_Return>", "\r").replace("<Null_Character>", "\0").replace("<ASCII_Bell>", "\a").replace("<ASCII_Backspace>", "\b").replace("<ASCII_Form_Feed>", "\f").replace("<ASCII_Vertical_Tab>", "\v"),
                vernamKey=str(key[:-2]),
                subsitutionKey=int(key[-2:])
                ) # Decryption
            ).strip().replace("\n", ' ').replace("\0", '').replace("\a", '')
        
        if len(mail) > 30:
            tempResponse.append(mail[:30])
        elif len(mail) <= 30:
            tempResponse.append(mail.ljust(30).replace(" ", "&nbsp;"))
        
        response.append(tempResponse)
    
    connection.close()
    return render_template("inbox.html", mail=response)

# Objective 3 started
@app.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def messages_compose():
    if request.method == 'GET':
        return render_template("compose.html", msg="")
    
    currentUser = current_user.get_user_dictionary()
    recipient = request.form.get('recipient')
    message = request.form.get('message')
    readReceipts = request.form.get('read-receipts')
    attachments = request.files.getlist('attachments')
    
    #Email validation
    cleanedEmail = entry_cleaner(recipient, "email")
    if cleanedEmail != recipient.lower(): # Error Handling
        print("Invalid email")
        data = [recipient, message, readReceipts]
        return render_template("compose.html", data=data, msg="Email is invalid", entry=["recipient"])
    del recipient
    
    if readReceipts == "True":
        readReceipts = True
    else:
        readReceipts = False

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT StaffID FROM Staff WHERE Email=? and AccountArchived='False';"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Invalid email")
        connection.close()
        data = [cleanedEmail, message, readReceipts]
        return render_template("compose.html", data=data, msg="Email is invalid", entry=["recipient"])
    else:
        recipientID = result[0]

    timeStamp = float(datetime.timestamp(datetime.now()))
    
    vernamKey = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(message)))
    subsitutionKey = random.randint(1, 61)

    cleanedMessage = message.replace('\0', '')
    
    encryptedMessage = encryption.encrypt(cleanedMessage, vernamKey=vernamKey, subsitutionKey=subsitutionKey)
    if subsitutionKey < 10:
        subsitutionKey = "0" + str(subsitutionKey)
        
    with open("secrets.json", "r") as f: # Reading from files
        key = encryption.substitution_encrypt(
            plainText=(vernamKey + str(subsitutionKey)),
            key=json.load(f)['MessageKey']
            ) # Encryption
    
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

    try:
        cursor.execute("""INSERT INTO Messages(SenderID, RecipientID, Message, HashedUrl, TimeStamp, ReadReceipts, Archived, Key)
                        VALUES (?, ?, ?, ?, ?, ?, 'False', ?);"""
                        , (
                            currentUser["id"],
                            recipientID,
                            cleanedEncryptedMessage,
                            str(uuid.uuid4()),
                            timeStamp,
                            str(readReceipts),
                            key
                            )
                        ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        data = [cleanedEmail, message, readReceipts]
        return render_template("compose.html", data=data, msg="Server Error")
    
    cursor.execute("""SELECT MessageID FROM Messages
                    WHERE SenderID=? and RecipientID=? and Message=? and TimeStamp=? and ReadReceipts=? and Key=?;"""
                    , (
                        currentUser["id"],
                        recipientID,
                        cleanedEncryptedMessage,
                        timeStamp,
                        str(readReceipts),
                        key
                        )
                    ) # Parameterised SQL
    result = cursor.fetchone()

    if result == None: # Error Handling
        connection.close()
        print("Failed to save message")
        data = [cleanedEmail, message, readReceipts]
        return render_template("compose.html", data=data, msg="Server Error")
    else:
        messageID = result[0]
    
    with open("secrets.json", "r") as f: # Reading from files
        cursor.execute("UPDATE Messages SET HashedUrl = ? WHERE MessageID = ?;"
                        , (encryption.substitution_encrypt(
                            plainText=str(uuid.uuid5(uuid.NAMESPACE_URL, str(messageID))),
                            key=json.load(f)['UrlKey']),
                            messageID) # Encryption
                        ) # Parameterised SQL
        connection.commit()
    
    connection.close()
    if attachments[0].filename != '':
        save_message_attachments(currentUser['id'], attachments, timeStamp, messageID, type="message")
    connection.close()
    return redirect(url_for('messages_compose'))
# Objective 3 completed

@app.route('/messages/inbox/<string:encryptedMessageID>', methods=['GET', 'POST'])
@login_required
def preview_message(encryptedMessageID):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT MessageID FROM Messages WHERE HashedUrl=?;"
                   , (encryptedMessageID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("URL not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    else:
        messageID = result[0]
    
    if request.method == 'POST':
        cursor.execute("UPDATE Messages SET Archived='True' WHERE MessageID=?;"
                       , (messageID, )
                       ) # Parameterised SQL
        connection.commit()
        print("Message archived")
        connection.close()
        return redirect(url_for('messages_inbox'))
    
    cursor.execute("SELECT * FROM Messages WHERE MessageID=?;"
                   , (messageID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Message not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    else:
        data = result
    
    if data[2] != current_user.id: # Error Handling
        print("Recipient isn't current user")
        connection.close()
        return redirect(url_for('messages_inbox'))
    
    if data[6] == "True":
        send_read_receipt(data)
    
    cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                   , (data[1], )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Sender not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    else:
        mail = [result[0]]
        
    with open("secrets.json", "r") as f:
        key = encryption.substitution_decrypt(encryptedText=data[8], key=json.load(f)['MessageKey']) # Decryption
            
    mail.append(
        str(
            encryption.decrypt(
                cipherText=data[3].replace("<Double_Quote>", "\"").replace("<Single_Quote>", "\'").replace("<Escape>", "\\").replace("<New_Line>", "\n").replace("<Tab>", "\t").replace("<Carriage_Return>", "\r").replace("<Null_Character>", "\0").replace("<ASCII_Bell>", "\a").replace("<ASCII_Backspace>", "\b").replace("<ASCII_Form_Feed>", "\f").replace("<ASCII_Vertical_Tab>", "\v"),
                vernamKey=str(key[:-2]),
                subsitutionKey=int(key[-2:])
            ) # Decryption
        ).replace("\0", '').replace("\a", '')
    )
    
    timestamp = datetime.fromtimestamp(float(data[5]))
    mail.append(
        f"{timestamp.strftime('%a')} {timestamp.strftime('%d')} {timestamp.strftime('%b')} {timestamp.strftime('%y')} at {timestamp.strftime('%I')}:{timestamp.strftime('%M')}{timestamp.strftime('%p').lower()}"
    )
    
    mail.append(data[4])
    
    cursor.execute("SELECT * FROM Files WHERE Origin=?;"
                   , (f"m+{messageID}", )
                   ) # Parameterised SQL
    result = cursor.fetchall()
    if result == None or len(result) == 0:
        mail.append([])
        connection.close()
        print("No attachments")
        return render_template("messages.html", mail=mail)
    
    attachments = []
    
    for attachment in result:
        attachments.append(
            (attachment[3].split('/')[-1], attachment[4])
        )
    
    mail.append(attachments)
    
    connection.close()
    return render_template("messages.html", mail=mail)

@app.route('/uploads/<string:encryptedAttachmentID>', methods=['GET'])
@login_required
def download_user_content(encryptedAttachmentID):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute("SELECT FilePath FROM Files WHERE HashedUrl=?;"
                   , (encryptedAttachmentID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("File not found")
        connection.close()
        return redirect(url_for('messages_inbox'))
    print("Sending file")
    connection.close()
    return send_file(result[0], as_attachment=True)

# Objective 7 started
@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reporting_search():
    if request.method == 'POST':
        dataString = request.form.get('email-list')
        if not dataString: # Error Handling
            return redirect(url_for('reporting_search'))
        
        data = dataString.split("|")
        if len(data) != 3: # Error Handling
            return redirect(url_for('reporting_search'))
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("SELECT StudentID FROM Students WHERE FirstName = ? and LastName = ? and DateOfBirth = ?;"
                       , (data[0], data[1], data[2])
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            print("No accounts found")
            connection.close()
            return redirect(url_for("reporting_search"))
        else:
            return redirect(url_for('student_reports', studentID=result[0]))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    if current_user.senco or current_user.safeguarding:
        cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students;")
        result = cursor.fetchall()
        if result == None or len(result) == 0: # Error Handling
            print("No accounts found")
            connection.close()
            return render_template("report_lookup.html", msg="empty")
        
        names = []
        for name in result:
            names.append((f"{name[0]} {name[1]}", f"{name[0]}|{name[1]}|{name[2]}"))
        
        connection.close()
        return render_template("report_lookup.html", names=names)
    
    cursor.execute("SELECT StudentID FROM StudentRelationship WHERE StaffID=?;"
                   , (current_user.id, )
                   ) # Parameterised SQL
    students = cursor.fetchall()
    if students == None or len(students) == 0: # Error Handling
        print("No links found")
        connection.close()
        return render_template("report_lookup.html", msg="empty")
    
    names=[]
    for student in students:
        cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                       , (student[0], )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            print("No students found")
            connection.close()
            return render_template("report_lookup.html", msg="empty")
        
        names.append((f"{result[0]} {result[1]}", f"{result[0]}|{result[1]}|{result[2]}"))
    
    connection.close()
    return render_template("report_lookup.html", names=names)

@app.route('/reports/<string:studentID>', methods=['GET'])
@login_required
def student_reports(studentID):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("reporting_search"))
    del studentID
    
    cursor.execute("SELECT Relationship FROM StudentRelationship WHERE StudentID=? and StaffID=?;"
                   , (cleanedID, current_user.id)
                   ) # Parameterised SQL
    result = cursor.fetchone()
    
    if result == None and not (current_user.senco or current_user.safeguarding): # Error Handling
        print("No relationship found")
        connection.close()
        return redirect(url_for("reporting_search"))

    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                   , (cleanedID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None or len(result) == 0: # Error Handling
        print("No student")
        connection.close()
        return redirect(url_for("reporting_search"))
    
    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                   , (cleanedID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("No students found")
        connection.close()
        return render_template("report_lookup.html", msg="empty")
    
    studentData = (f"{result[0]} {result[1]}", result[2])
    
    return render_template("student_profile.html", studentData=studentData, studentID=cleanedID)

@app.route('/reports/view/<string:studentID>', methods=['GET'])
@login_required
def view_reports(studentID):
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("reporting_search"))
    cleanedID = int(cleanedID)
    del studentID
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT Relationship FROM StudentRelationship WHERE StudentID=? and StaffID=?;"
                    , (cleanedID, current_user.id)
                    ) # Parameterised SQL
    result = cursor.fetchone()
    
    if current_user.senco or current_user.safeguarding or result in [1, 2, 3, 0]:
        cursor.execute("SELECT * FROM Reporting WHERE StudentID=?;"
                    , (cleanedID, )
                    ) # Parameterised SQL
    else:
        cursor.execute("SELECT * FROM Reporting WHERE StudentID=? and StaffID=?;"
                    , (cleanedID, current_user.id)
                    ) # Parameterised SQL
    
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        return render_template("reports.html", msg="empty", studentID=cleanedID)
    else:
        reports = result

    response = [] # A list of reports

    for report in reports:
        tempResponse = [report[1]]
        
        cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                       , (report[2], )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Sender not found")
            return redirect(url_for('reporting_search'))
        else:
            tempResponse.append(result[0])
        
        timestamp = datetime.fromtimestamp(float(report[5]))
        tempResponse.append(
            f"{timestamp.strftime('%a')} {timestamp.strftime('%d')} {timestamp.strftime('%b')} {timestamp.strftime('%y')} at {timestamp.strftime('%I')}:{timestamp.strftime('%M')}{timestamp.strftime('%p').lower()}"
            )
        tempResponse.append(result[0])
        
        tempResponse.append(report[0])
        
        response.append(tempResponse)
    
    connection.close()
    return render_template("reports.html", data=response, studentID=cleanedID)

@app.route('/reports/view/<string:studentID>/<string:reportID>', methods=['GET'])
@login_required
def preview_report(studentID, reportID):
    cleanedStudentID = entry_cleaner(studentID, "sql")
    if studentID != cleanedStudentID: # Error Handling
        print("Invalid student ID")
        return redirect(url_for("reporting_search"))
    cleanedStudentID = int(cleanedStudentID)
    del studentID
    
    cleanedReportID = entry_cleaner(reportID, "sql")
    if reportID != cleanedReportID: # Error Handling
        print("Invalid report ID")
        return redirect(url_for("reporting_search"))
    cleanedReportID = int(cleanedReportID)
    del reportID
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT * FROM Reporting WHERE ReportID=?;"
                   , (cleanedReportID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Report not found")
        connection.close()
        return redirect(url_for('view_reports', studentID=cleanedStudentID))
    else:
        data = result

    if data[1] != cleanedStudentID: # Error Handling
        return redirect(url_for("reporting_search"))
    
    cursor.execute("SELECT Relationship FROM StudentRelationship WHERE StudentID=? and StaffID=?;"
                    , (cleanedStudentID, current_user.id)
                    ) # Parameterised SQL
    
    if current_user.id != data[2] and not (current_user.senco or current_user.safeguarding) and result not in [1, 2, 3, 0]: # Error Handling
        print("No permission no view report")
        connection.close()
        return redirect(url_for("reporting_search"))
    
    with open("secrets.json", "r") as f: # Reading from files
        key = encryption.substitution_decrypt(encryptedText=data[6], key=json.load(f)['ReportKey']) # Decryption
    
    cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                   , (data[2], )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Reporter not found")
        connection.close()
        return redirect(url_for('view_reports', studentID=cleanedStudentID))
    else:
        report = [result[0]]
    
    
    report.append(
        str(
            encryption.decrypt(
                cipherText=data[3].replace("<Double_Quote>", "\"").replace("<Single_Quote>", "\'").replace("<Escape>", "\\").replace("<New_Line>", "\n").replace("<Tab>", "\t").replace("<Carriage_Return>", "\r").replace("<Null_Character>", "\0").replace("<ASCII_Bell>", "\a").replace("<ASCII_Backspace>", "\b").replace("<ASCII_Form_Feed>", "\f").replace("<ASCII_Vertical_Tab>", "\v"),
                vernamKey=str(key[:-2]),
                subsitutionKey=int(key[-2:])
            ) # Decryption
        ).replace("\0", '').replace("\a", '')
    )
    
    timestamp = datetime.fromtimestamp(float(data[5]))
    report.append(
        f"{timestamp.strftime('%a')} {timestamp.strftime('%d')} {timestamp.strftime('%b')} {timestamp.strftime('%y')} at {timestamp.strftime('%I')}:{timestamp.strftime('%M')}{timestamp.strftime('%p').lower()}"
    )
    
    report.append(data[4])
    
    cursor.execute("SELECT * FROM Files WHERE Origin=?;"
                   , (f"r+{cleanedReportID}", )
                   ) # Parameterised SQL
    result = cursor.fetchall()

    if result == None or len(result) == 0: # Error Handling
        report.append([])
        connection.close()
        print("No attachments")
        return render_template("report.html", mail=report)
    
    attachments = []
    
    for attachment in result:
        attachments.append(
            (attachment[3].split('/')[-1], attachment[4])
        )
    
    report.append(attachments)
    
    connection.close()
    return render_template("report.html", mail=report)
# Objective 7 completed

@app.route('/reports/write/<string:studentID>', methods=['GET', 'POST'])
@login_required
def create_report(studentID):
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("reporting_search"))
    del studentID
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                   , (cleanedID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Student not found")
        connection.close()
        return redirect(url_for("reporting_search"))
    
    studentName = f"{result[0]} {result[1]}"
    if request.method == 'GET':
        connection.close()
        print(cleanedID + " | " +  studentName)
        return render_template("write_report.html", msg="", studentID=cleanedID, studentName=studentName)
    
    currentUser = current_user.get_user_dictionary()
    message = request.form.get('message')
    attachments = request.files.getlist('attachments')

    timeStamp = float(datetime.timestamp(datetime.now()))
    
    vernamKey = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(message)))
    subsitutionKey = random.randint(1, 61)

    cleanedMessage = message.replace('\0', '')
    
    encryptedMessage = encryption.encrypt(cleanedMessage, vernamKey=vernamKey, subsitutionKey=subsitutionKey)
    if subsitutionKey < 10:
        subsitutionKey = "0" + str(subsitutionKey)
    
    with open("secrets.json", "r") as f: # Reading from files
        key = encryption.substitution_encrypt(
            plainText=(vernamKey + str(subsitutionKey)),
            key=json.load(f)['ReportKey']
            ) # Encryption
    
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

    randomURL = str(uuid.uuid4())

    try:
        cursor.execute("""INSERT INTO Reporting(StudentID, StaffID, Report, URL, TimeStamp, Key)
                        VALUES (?, ?, ?, ?, ?, ?);"""
                        , (
                            cleanedID,
                            currentUser["id"],
                            cleanedEncryptedMessage,
                            randomURL,
                            timeStamp,
                            key
                            )
                        ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        return render_template("write_report.html", reportContent=message, msg="Server Error", studentID=cleanedID, studentName=studentName)
    
    cursor.execute("""SELECT ReportID FROM Reporting
                    WHERE StudentID=? and StaffID=? and Report=? and URL=? and TimeStamp=? and Key=?;"""
                    , (
                        cleanedID,
                        currentUser["id"],
                        cleanedEncryptedMessage,
                        randomURL,
                        timeStamp,
                        key
                        )
                    ) # Parameterised SQL
    result = cursor.fetchone()

    if result == None: # Error Handling
        connection.close()
        print("Failed to save message")
        return render_template("write_report.html", reportContent=message, msg="Server Error", studentID=cleanedID, studentName=studentName)
    else:
        reportID = result[0]
    
    connection.close()
    if attachments[0].filename != '':
        save_message_attachments(currentUser['id'], attachments, timeStamp, reportID, type="report")
    connection.close()
    return render_template("write_report.html", msg="Report Filed Successfully", studentID=cleanedID, studentName=studentName, id="submit")

@app.route('/alerts', methods=['GET'])
@login_required
def alerts_page():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT NotificationID, BannerMessage, URL, TimeStamp, Ephemeral FROM Notifications WHERE RecipientID=?;"
                   , (current_user.id, )
                   ) # Parameterised SQL
    result = cursor.fetchall()
    
    if result == None or len(result) == 0: # Error Handling
        print("No notifications found")
        connection.close()
        return render_template('alerts_home.html', notifications=[])
    
    data = []
    
    for notification in result:
        if float(notification[3]) >= float(datetime.timestamp(datetime.now())) or notification[4] == "True":
            if len(notification[1]) > 30:
                header = (notification[1][:30])
            elif len(notification[1]) <= 30:
                header = (notification[1].ljust(30).replace(" ", "&nbsp;"))
            data.append(
                    {
                        "message": header,
                        "link": url_for('alerts_view', notificationID=notification[2])
                    }
                )
        else:
            cursor.execute("DELETE FROM Notifications WHERE NotificationID = ?;"
                        , (notification[0], )
                        ) # Parameterised SQL
            connection.commit()
    
    connection.close()
    return render_template('alerts_home.html', notifications=data)

@app.route('/alerts/view/<string:notificationID>', methods=['GET', 'POST'])
def alerts_view(notificationID):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT NotificationID FROM Notifications WHERE URL=?;"
                   , (notificationID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("URL not found")
        connection.close()
        return redirect(url_for('alerts_page'))
    else:
        cleanedNotificationID = result[0]
    
    cursor.execute("SELECT * FROM Notifications WHERE NotificationID=?;"
                   , (cleanedNotificationID, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Notification not found")
        connection.close()
        return redirect(url_for('alerts_page'))
    
    if result[2] != current_user.id: # Error Handling
        print("Recipient isn't current user")
        connection.close()
        return redirect(url_for('alerts_page'))
    
    if request.method == 'POST':
        cursor.execute("DELETE FROM Notifications WHERE NotificationID=?;"
                    , (cleanedNotificationID, )
                    ) # Parameterised SQL
        connection.commit()
        return redirect(url_for('alerts_page'))
    
    data = result
    
    cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                   , (data[1], )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("Sender not found")
        connection.close()
        return redirect(url_for('alerts_page'))
    
    notification = [
        result[0],
        data[4]
        ]
    
    if data[7] == "True":
        cursor.execute("DELETE FROM Notifications WHERE NotificationID=?;"
                       , (cleanedNotificationID, )
                       ) # Parameterised SQL
        connection.commit()
    
    connection.close()
    return render_template("alerts_view.html", notification=notification, notificationID=notificationID, ephemeral=data[7])

@app.route('/alerts/send', methods=['GET', 'POST'])
@login_required
def alerts_send():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT Email FROM Staff WHERE AccountArchived='False' and StaffID!=?;"
                   , (current_user.id, )
                   ) # Parameterised SQL
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        print("No accounts found")
        connection.close()
        
        return render_template('alerts_send.html', msg="")
    else:
        data = result
    
    emails = []
    for email in data:
        emails.append(email[0])
    
    if request.method == 'GET':
        connection.close()
        return render_template('alerts_send.html', emails=emails, msg="")
    
    staffEmail = request.form.get('email-list')
    staffRole = request.form.get('role-list')
    bannerMessage = request.form.get('banner')
    message = request.form.get('message')
    timePeriod = request.form.get('time-period')
    
    if staffEmail == "_" and staffRole == "_": # Error Handling
        print("Invalid staff member/role")
        connection.close()
        
        data = [staffEmail, staffRole, bannerMessage, message, timePeriod]
        return render_template("alerts_send.html", emails=emails, data=data, msg="Please select a recipient", entry=["staff", "role"])
    
    if staffRole not in ["_", "1", "2", "3", "0"]: # Error Handling
        print("Invalid staff role")
        connection.close()
        
        data = [staffEmail, staffRole, bannerMessage, message, timePeriod]
        return render_template("alerts_send.html", emails=emails, data=data, msg="Invalid staff role", entry=["role"])
    else:
        cleanedStaffRole = {
            "_": "_",
            "1": "SENCo",
            "2": "Safeguarding",
            "3": "Admin",
            "0": "Other"
            }[staffRole]
    
    cleanedBannerMessage = entry_cleaner(bannerMessage, "sql").replace("\0", '').replace("\a", '')
    if cleanedBannerMessage != bannerMessage: # Error Handling
        print("Invalid first name")
        connection.close()
        
        data = [staffEmail, staffRole, bannerMessage, message, timePeriod]
        return render_template("alerts_send.html", emails=emails, data=data, msg="Invalid banner message", entry=["banner"])
    del bannerMessage
    
    cleanedMessage = entry_cleaner(message, "sql").replace("\0", '').replace("\a", '')
    if cleanedMessage != message: # Error Handling
        print("Invalid last name")
        connection.close()
        
        data = [staffEmail, staffRole, cleanedBannerMessage, message, timePeriod]
        return render_template("alerts_send.html", emails=emails, data=data, msg="Invalid message", entry=["message"])
    del message
    
    if timePeriod not in ["eph", "15m", "30m", "1h", "24h"]: # Error Handling
        print("Invalid time period")
        connection.close()
        
        data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
        return render_template("alerts_send.html", emails=emails, data=data, msg="Invalid time period", entry=["time-period"])
    
    ephemeralNotification = False
    if timePeriod == "eph":
        timeStamp = float(datetime.timestamp(datetime.now()))
        ephemeralNotification = True
    elif timePeriod == "15m":
        timeStamp = float((datetime.now() + timedelta(minutes=15)).timestamp())
    elif timePeriod == "30m":
        timeStamp = float((datetime.now() + timedelta(minutes=30)).timestamp())
    elif timePeriod == "1h":
        timeStamp = float((datetime.now() + timedelta(hours=1)).timestamp())
    elif timePeriod == "24h":
        timeStamp = float((datetime.now() + timedelta(days=1)).timestamp())
    
    recipients = []
    if staffEmail != "_":
        cursor.execute("SELECT StaffID FROM Staff WHERE Email=?;"
                        , (staffEmail, )
                        ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            print("User not found")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="Server Error")
        recipients.append(result[0])
    
    if cleanedStaffRole == "SENCo":
        cursor.execute("SELECT StaffID FROM Staff WHERE SENCo='True' and AccountArchived='False' and AccountEnabled='True';")
        result = cursor.fetchall()
        if result == None or len(result) == 0: # Error Handling
            print("Users not found")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="No SENCo staff found")
        
        for staffID in result:
            recipients.append(staffID[0])
    
    elif cleanedStaffRole == "Safeguarding":
        cursor.execute("SELECT StaffID FROM Staff WHERE Safeguarding='True' and AccountArchived='False' and AccountEnabled='True';")
        result = cursor.fetchall()
        if result == None or len(result) == 0: # Error Handling
            print("Users not found")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="No safeguarding staff found")
        
        for staffID in result:
            recipients.append(staffID[0])
    
    elif cleanedStaffRole == "Admin":
        cursor.execute("SELECT StaffID FROM Staff WHERE Admin='True' and AccountArchived='False' and AccountEnabled='True';")
        result = cursor.fetchall()
        if result == None or len(result) == 0: # Error Handling
            print("Users not found")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="No admin staff found")
        
        for staffID in result:
            recipients.append(staffID[0])
    
    elif cleanedStaffRole == "Other":
        cursor.execute("SELECT StaffID FROM Staff WHERE SENCo='False' and Safeguarding='False' and Admin='False' and AccountArchived='False' and AccountEnabled='True';")
        result = cursor.fetchall()
        if result == None: # Error Handling
            print("Users not found")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="No staff found without roles found")
        
        for staffID in result:
            recipients.append(staffID[0])
    
    
    for recipientID in recipients:
        try:
            cursor.execute("""INSERT INTO Notifications(SenderID, RecipientID, BannerMessage, Message, URL, TimeStamp, Ephemeral)
                        VALUES (?, ?, ?, ?, ?,?, ?);"""
                        , (
                            current_user.id,
                            recipientID,
                            cleanedBannerMessage,
                            cleanedMessage,
                            str(uuid.uuid4()),
                            timeStamp,
                            str(ephemeralNotification)
                            )
                        ) # Parameterised SQL
            connection.commit()
        except sqlite3.IntegrityError: # Error Handling
            print("Failed CHECK constraint")
            connection.close()
            
            data = [staffEmail, staffRole, cleanedBannerMessage, cleanedMessage, timePeriod]
            return render_template("alerts_send.html", emails=emails, data=data, msg="Server Error")
    
    connection.close()
    return render_template("alerts_send.html", emails=emails, msg="Sent alert", entry=["submit"])

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if request.method == 'GET':
        return render_template("user_settings.html", msg="", entry=[])
    
    email = request.form.get('email')
    oldPassword = request.form.get('old-password')
    newPassword = request.form.get('new-password')
    confirmNewPassword = request.form.get('confirm-new-password')

    #Email validation
    cleanedEmail = entry_cleaner(email, "email")
    if cleanedEmail != email.lower(): # Error Handling
        print("Invalid email")
        return render_template("user_settings.html", msg="Invalid Email", entry=["email"], savedEmail=email)
    del email
    
    #Password Validation
    cleanedOldPassword = entry_cleaner(oldPassword, "password")
    cleanedNewPassword = entry_cleaner(newPassword, "password")
    cleanedConfirmNewPassword = entry_cleaner(confirmNewPassword, "password")
    if cleanedOldPassword != oldPassword: # Error Handling
        print("Invalid old password")
        return render_template("user_settings.html", msg="Old password contains illegal characters", entry=["old-password"], savedEmail=cleanedEmail)
    if cleanedNewPassword != newPassword: # Error Handling
        print("Invalid new password")
        return render_template("user_settings.html", msg="New password contains illegal characters", entry=["new-password"], savedEmail=cleanedEmail)
    if cleanedConfirmNewPassword != confirmNewPassword: # Error Handling
        print("Invalid confirm new password")
        return render_template("user_settings.html", msg="Confirm new password contains illegal characters", entry=["confirm-new-password"], savedEmail=cleanedEmail)
    del oldPassword
    del newPassword
    del confirmNewPassword

    if not check_password_strength(cleanedNewPassword):
        print("Insecure password")
        return render_template("user_settings.html", msg="Insecure password", entry=["new-password","confirm-new-password"], savedEmail=cleanedEmail)
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    # Checking email
    cursor.execute("SELECT Email FROM Staff WHERE StaffID=?;"
                    , (current_user.id, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"], savedEmail=cleanedEmail)
    elif result[0].lower() != cleanedEmail.lower(): # Error Handling
        connection.close()
        print("Invalid email")
        return render_template("user_settings.html", msg="Your email contains illegal characters", entry=["email"], savedEmail=cleanedEmail)
    
    # Getting user's password
    cursor.execute("SELECT passHash FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"], savedEmail=cleanedEmail)
    else:
        passHash = result[0]
    
    cursor.execute("SELECT passSalt FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("User not found")
        return render_template("user_settings.html", msg="The email you entered isn't your email", entry=["email"], savedEmail=cleanedEmail)
    else:
        salt = result[0]
    
    if passHash != hash_function.hash_variable(cleanedOldPassword, salt): # Hashing
        connection.close()
        print("Old password isn't valid")
        return render_template("user_settings.html", msg="Your old password doesn't match the password that you entered", entry=["old-password"], savedEmail=cleanedEmail)
    
    if cleanedNewPassword != cleanedConfirmNewPassword: # Error Handling
        connection.close()
        print("New password and confirm new password aren't the same")
        return render_template("user_settings.html", msg="Please use the same new password when confirming your new password", entry=["new-password", "confirm-new-password"], savedEmail=cleanedEmail)
    
    cursor.execute("UPDATE Staff SET PassHash = ? WHERE StaffID=?;"
                    , (hash_function.hash_variable(
                        cleanedNewPassword,
                        salt),
                        ), # Hashing
                    current_user.id
                    ) # Parameterised SQL
    connection.commit()
    
    userDetails = current_user.get_user_dictionary()
    userDetails["passhash"] = hash_function.hash_variable(cleanedNewPassword, salt) # Hashing
    logout_user()
    login_user(User(userDetails), remember=False) # Dynamic generation of objects
    return render_template("user_settings.html", msg="Password changed successfully", entry=["submit"])

@app.route('/app/analytics', methods=['GET'])
@login_required
def analytics():# TODO
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    return render_template("under_construction.html")

@app.route('/app/users', methods=['GET'])
@login_required
def manage_user():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    return render_template("manage_users.html")

@app.route('/app/users/staff', methods=['GET'])
@login_required
def manage_users_staff():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    return render_template("manage_staff.html")

@app.route('/app/users/students', methods=['GET'])
@login_required
def manage_users_students():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    return render_template("manage_students.html")

@app.route('/app/users/staff/create', methods=['GET', 'POST'])
@login_required
def create_staff():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        return render_template("create_staff.html", msg="")
    
    email = request.form.get('email')
    fName = request.form.get('first-name')
    lName = request.form.get('last-name')
    title = request.form.get('title')
    senco = request.form.get('senco')
    safeguarding = request.form.get('safeguarding')
    admin = request.form.get('admin')
    enabled = request.form.get('enabled')
    password = request.form.get('password')
    
    
    if senco != "True":
        senco = "False"
    
    if safeguarding != "True":
        safeguarding = "False"
    
    if admin != "True":
        admin = "False"
    
    if enabled != "True":
        enabled = "False"
    
    cleanedEmail = entry_cleaner(email, "email")
    if cleanedEmail != email: # Error Handling
        print("Invalid email")
        data = [email, fName, lName, title, senco, safeguarding, admin, enabled, password]
        return render_template("create_staff.html", data=data, msg="Email is invalid", entry=["email"])
    del email
    
    cleanedFName = entry_cleaner(fName, "sql")
    if cleanedFName != fName: # Error Handling
        print("Invalid first name")
        data = [cleanedEmail, fName, lName, title, senco, safeguarding, admin, enabled, password]
        return render_template("create_staff.html", data=data, msg="First name is invalid", entry=["first-name"])
    del fName
    
    cleanedLName = entry_cleaner(lName, "sql")
    if cleanedLName != lName: # Error Handling
        print("Invalid last name")
        data = [cleanedEmail, cleanedFName, lName, title, senco, safeguarding, admin, enabled, password]
        return render_template("create_staff.html", data=data, msg="Last name is invalid", entry=["last-name"])
    del lName
    
    cleanedTitle = entry_cleaner(title, "sql")
    if cleanedTitle != title: # Error Handling
        print("Invalid title")
        data = [cleanedEmail, cleanedFName, cleanedLName, title, senco, safeguarding, admin, enabled, password]
        return render_template("create_staff.html", data=data, msg="Title is invalid", entry=["title"])
    del title
    
    cleanedPassword = entry_cleaner(password, "password")
    if cleanedPassword != password: # Error Handling
        print("Invalid old password")
        data = [cleanedEmail, cleanedFName, cleanedLName, cleanedTitle, senco, safeguarding, admin, enabled, password]
        return render_template("create_staff.html", data=data, msg="Password is invalid", entry=["password"])
    del password
    
    if cleanedPassword != "ChangeMe":
        if not check_password_strength(cleanedPassword):
            print("Insecure password")
            data = [cleanedEmail, cleanedFName, cleanedLName, cleanedTitle, senco, safeguarding, admin, enabled, cleanedPassword]
            return render_template("create_staff.html", data=data, msg="Password is insecure", entry=["password"])

    passwordSalt = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(len(cleanedPassword)))
    passwordHash = hash_function.hash_variable(cleanedPassword, passwordSalt) # Hashing
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    try:
        cursor.execute("""INSERT INTO Staff(FirstName, LastName, Title, Email, AccountEnabled, AccountArchived, PassHash, PassSalt, SENCo, Safeguarding, Admin)
                       VALUES (?, ?, ?, ?, ?, 'False', ?, ?, ?, ?, ?);"""
                       , (
                           cleanedFName,
                           cleanedLName,
                           cleanedTitle,
                           cleanedEmail,
                           enabled,
                           passwordHash,
                           passwordSalt,
                           senco,
                           safeguarding,
                           admin
                           )
                       ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        connection.close()
        data = [cleanedEmail, cleanedFName, cleanedLName, cleanedTitle, senco, safeguarding, admin, enabled, cleanedPassword]
        return render_template("create_staff.html", data=data, msg="Server Error")

    connection.close()
    return render_template("create_staff.html", msg="Created user account", entry=["submit"])

@app.route('/app/users/staff/lookup', methods=['GET', 'POST'])
@login_required
def search_staff():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email-list')
        if email:
            return redirect(url_for('edit_staff', staffEmail=email))
        return redirect(url_for('search_staff'))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT Email FROM Staff WHERE AccountArchived='False';")
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        print("No accounts found")
        connection.close()
        return redirect(url_for("search_staff"))
    else:
        data = result
    
    emails = []
    for email in data:
        emails.append(email[0])
    
    return render_template("manage_staff_lookup.html", emails=emails)

@app.route('/app/users/staff/edit/<string:staffEmail>', methods=['GET', 'POST'])
@login_required
def edit_staff(staffEmail):
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        cleanedEmail = entry_cleaner(staffEmail, "email")
        if staffEmail != cleanedEmail: # Error Handling
            print("Invalid Email")
            return redirect(url_for("search_staff"))
        del staffEmail
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM Staff WHERE Email=?;"
                       , (cleanedEmail, )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Target user not found")
            return redirect(url_for("search_staff"))
        
        data = [
            result[1],  #FirstName
            result[2],  #LastName
            result[3],  #Title
            result[4],  #Email
            result[5],  #Enabled
            result[9],  #SENCo
            result[10], #Safeguarding
            result[11]  #Admin
            ]

        return render_template("edit_staff.html", data=data, msg="")
    
    cleanedStaffEmail = entry_cleaner(staffEmail, "sql")
    if staffEmail != cleanedStaffEmail: # Error Handling
        print("Invalid ID")
        return redirect(url_for("search_students"))
    del staffEmail
    
    email = request.form.get('email')
    title = request.form.get('title')
    firstName = request.form.get('first-name')
    lastName = request.form.get('last-name')
    senco = request.form.get('senco')
    safeguarding = request.form.get('safeguarding')
    admin = request.form.get('admin')
    enabled = request.form.get('enabled')
    resetPassword = request.form.get('password')
    deleteAccount = request.form.get('delete')
    
    if senco != "True":
        senco = "False"
    
    if safeguarding != "True":
        safeguarding = "False"
    
    if admin != "True":
        admin = "False"
    
    if enabled != "True":
        enabled = "False"
    
    if resetPassword != "True":
        resetPassword = "False"
    
    if deleteAccount != "True":
        deleteAccount = "False"
    
    cleanedEmail = entry_cleaner(email, "email")
    if cleanedEmail != email: # Error Handling
        print("Invalid email")
        data = [firstName, lastName, title, email, enabled, senco, safeguarding, admin]
        return render_template("edit_staff.html", data=data, msg="Email is invalid", entry=["email"])
    del email
    
    cleanedFName = entry_cleaner(firstName, "sql")
    if cleanedFName != firstName: # Error Handling
        print("Invalid first name")
        data = [firstName, lastName, title, cleanedEmail, enabled, senco, safeguarding, admin]
        return render_template("edit_staff.html", data=data, msg="First name is invalid", entry=["first-name"])
    del firstName
    
    cleanedLName = entry_cleaner(lastName, "sql")
    if cleanedLName != lastName: # Error Handling
        print("Invalid last name")
        data = [cleanedFName, lastName, title, cleanedEmail, enabled, senco, safeguarding, admin]
        return render_template("edit_staff.html", data=data, msg="Last name is invalid", entry=["last-name"])
    del lastName
    
    cleanedTitle = entry_cleaner(title, "sql")
    if cleanedTitle != title: # Error Handling
        print("Invalid title")
        data = [cleanedFName, cleanedLName, title, cleanedEmail, enabled, senco, safeguarding, admin]
        return render_template("edit_staff.html", data=data, msg="Title is invalid", entry=["title"])
    del title
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT Admin FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("Target user not found")
        return redirect(url_for("search_staff"))
    
    if admin == "False" and result[0] == "True":
        cursor.execute("SELECT StaffID FROM Staff WHERE Admin='True' and AccountArchived='False' and AccountEnabled='True';")
        result = cursor.fetchall()
        if result == None or len(result) == 0: # Error Handling
            connection.close()
            print("Target user not found")
            return redirect(url_for("search_staff"))
        if len(result) == 1: # Error Handling
            data = [cleanedFName, cleanedLName, cleanedTitle, cleanedEmail, enabled, senco, safeguarding, "True"]
            print("User is trying to remove last admin")
            return render_template("edit_staff.html", data=data, msg="There must always be at least one admin account active", entry=["admin"])
    
    cursor.execute("SELECT StaffID, Passhash, PassSalt FROM Staff WHERE Email=?;"
                    , (cleanedEmail, )
                    ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("Target user not found")
        return redirect(url_for("search_staff"))
    
    if resetPassword == "True":
        print(resetPassword)
        passHash = hash_function.hash_variable("ChangeMe", result[2]) # Hashing
    else:
        passHash = result[1]

    if deleteAccount == "True":
        cursor.execute("DELETE FROM StudentRelationship WHERE StaffID = ?;"
                        , (result[0], )
                        ) # Parameterised SQL
        connection.commit()
        enabled = "False"
        archived = "True"
        senco = "False"
        safeguarding = "False"
        admin = "False"
    else:
        archived = "False"
    
    try:
        cursor.execute("UPDATE Staff SET FirstName = ?, Lastname = ?, Title = ?, Email = ?, AccountEnabled = ?, AccountArchived = ?, PassHash = ?, PassSalt = ?, SENCo = ?, Safeguarding = ?, Admin = ? WHERE Email = ?"
                        , (
                            cleanedFName,
                            cleanedLName,
                            cleanedTitle,
                            cleanedEmail,
                            enabled,
                            archived,
                            passHash,
                            result[2],
                            senco,
                            safeguarding,
                            admin,
                            cleanedEmail
                            )
                        ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        connection.close()
        data = [cleanedFName, cleanedLName, cleanedTitle, cleanedEmail, enabled, senco, safeguarding, admin]
        return render_template("create_staff.html", data=data, msg="Server Error")
    
    if current_user.id == result[0]:
        userDetails = current_user.get_user_dictionary()
        logout_user()
        login_user(User(userDetails), remember=False) # Dynamic generation of objects
    
    if current_user.get_user_dictionary()["admin"] == "False":
        return redirect(url_for("dashboard"))
    
    if deleteAccount == "True":
        return redirect(url_for('search_staff'))
    
    data = [cleanedFName, cleanedLName, cleanedTitle, cleanedEmail, enabled, senco, safeguarding, admin]
    return render_template("edit_staff.html", data=data, msg=f"Successfully updated {cleanedEmail}'s account")

@app.route('/app/users/students/create', methods=['GET', 'POST'])
@login_required
def create_student():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        return render_template("create_students.html", msg="")
    
    fName = request.form.get('first-name')
    lName = request.form.get('last-name')
    date = request.form.get('date')
    
    cleanedFName = entry_cleaner(fName, "sql")
    if cleanedFName != fName: # Error Handling
        print("Invalid first name")
        data = [fName, lName, date]
        return render_template("create_students.html", data=data, msg="First name is invalid", entry=["first-name"])
    del fName
    
    cleanedLName = entry_cleaner(lName, "sql")
    if cleanedLName != lName: # Error Handling
        print("Invalid last name")
        data = [cleanedFName, lName, date]
        return render_template("create_students.html", data=data, msg="Last name is invalid", entry=["last-name"])
    del lName
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    try:
        cursor.execute("INSERT INTO Students(FirstName, LastName, DateOfBirth) VALUES (?, ?, ?);"
                       , (cleanedFName, cleanedLName, date)
                       ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        connection.close()
        data = [cleanedFName, cleanedLName, date]
        return render_template("create_students.html", data=data, msg="Server Error")

    connection.close()
    return render_template("create_students.html", msg="Created user account", entry=["submit"])

@app.route('/app/users/students/lookup', methods=['GET', 'POST'])
@login_required
def search_students():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        dataString = request.form.get('email-list')
        if not dataString: # Error Handling
            return redirect(url_for('search_students'))
        
        data = dataString.split("|")
        if len(data) != 3: # Error Handling
            return redirect(url_for('search_students'))
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("SELECT StudentID FROM Students WHERE FirstName = ? and LastName = ? and DateOfBirth = ?;"
                       , (data[0], data[1], data[2])
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            print("No accounts found")
            connection.close()
            return redirect(url_for("search_students"))
        else:
            return redirect(url_for('edit_student', studentID=result[0]))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students;")
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        print("No accounts found")
        connection.close()
        return render_template("manage_student_lookup.html", msg="empty")
    else:
        data = result
    
    names = []
    for name in data:
        names.append((f"{name[0]} {name[1]}", f"{name[0]}|{name[1]}|{name[2]}"))
    
    return render_template("manage_student_lookup.html", names=names)

@app.route('/app/users/students/edit/<string:studentID>', methods=['GET', 'POST'])
@login_required
def edit_student(studentID):
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'GET':
        cleanedID = entry_cleaner(studentID, "sql")
        if studentID != cleanedID: # Error Handling
            print("Invalid ID")
            return redirect(url_for("search_students"))
        del studentID
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM Students WHERE StudentID=?;"
                       , (cleanedID, )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Target user not found")
            return redirect(url_for("search_students"))
        
        data = [
            str(result[0]), #ID
            result[1],      #FirstName
            result[2],      #LastName
            result[3],      #DateOfBirth
            ]

        return render_template("edit_student.html", data=data, msg="")
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("search_students"))
    del studentID
    
    firstName = request.form.get('first-name')
    lastName = request.form.get('last-name')
    dateOfBirth = request.form.get('date-of-birth')
    delete = request.form.get('delete')
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    if delete == "True":
        cursor.execute("DELETE FROM Reporting WHERE StudentID = ?;"
                        , (cleanedID, )
                        ) # Parameterised SQL
        connection.commit()
        cursor.execute("DELETE FROM StudentRelationship WHERE StudentID = ?;"
                        , (cleanedID, )
                        ) # Parameterised SQL
        connection.commit()
        cursor.execute("DELETE FROM Students WHERE StudentID = ?;"
                        , (cleanedID, )
                        ) # Parameterised SQL
        connection.commit()
        
        cursor.execute("SELECT StudentID FROM Students;")
        result = cursor.fetchall()
        connection.close()
        if result == None or len(result) == 0: # Error Handling
            return redirect(url_for("manage_users_students"))
        return redirect(url_for('search_students'))

    cleanedFName = entry_cleaner(firstName, "sql")
    if cleanedFName != firstName: # Error Handling
        print("Invalid first name")
        data = [cleanedID, firstName, lastName, dateOfBirth]
        return render_template("edit_student.html", data=data, msg="First name is invalid", entry=["first-name"])
    del firstName
    
    cleanedLName = entry_cleaner(lastName, "sql")
    if cleanedLName != lastName: # Error Handling
        print("Invalid last name")
        data = [cleanedID, cleanedFName, lastName, dateOfBirth]
        return render_template("edit_student.html", data=data, msg="Last name is invalid", entry=["last-name"])
    del lastName

    try:
        cursor.execute("UPDATE Students SET FirstName = ?, Lastname = ?, DateOfBirth = ? WHERE StudentID = ?"
                        , (
                            cleanedFName,
                            cleanedLName,
                            dateOfBirth,
                            cleanedID
                            )
                        ) # Parameterised SQL
        connection.commit()
    except sqlite3.IntegrityError: # Error Handling
        print("Failed CHECK constraint")
        connection.close()
        data = [cleanedID, cleanedFName, cleanedLName, dateOfBirth]
        return render_template("edit_student.html", data=data, msg="Server Error")
    
    data = [cleanedID, cleanedFName, cleanedLName, dateOfBirth]
    return render_template("edit_student.html", data=data, msg="Successfully updated!")

# Objective 6 started
@app.route('/app/users/students/Links', methods=['GET', 'POST'])
@login_required
def staff_student_relationships_lookup():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        dataString = request.form.get('email-list')
        if not dataString: # Error Handling
            return redirect(url_for('staff_student_relationships_lookup'))
        
        data = dataString.split("|")
        if len(data) != 3: # Error Handling
            return redirect(url_for('staff_student_relationships_lookup'))
        
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        cursor.execute("SELECT StudentID FROM Students WHERE FirstName = ? and LastName = ? and DateOfBirth = ?;"
                       , (data[0], data[1], data[2])
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            print("No accounts found")
            connection.close()
            return redirect(url_for("staff_student_relationships_lookup"))
        else:
            return redirect(url_for('staff_student_relationships', studentID=result[0]))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students;")
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        print("No accounts found")
        connection.close()
        return render_template("manage_student_lookup.html", msg="empty")
    else:
        data = result
    
    names = []
    for name in data:
        names.append((f"{name[0]} {name[1]}", f"{name[0]}|{name[1]}|{name[2]}"))
    
    return render_template("staff_student_relationships_lookup.html", names=names)

@app.route('/app/users/students/Links/All', methods=['GET'])
@login_required
def view_all_student_staff_relationships():
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    cursor.execute("SELECT Students.StudentID, Staff.StaffID, StudentRelationship.Relationship FROM StudentRelationship INNER JOIN Students ON StudentRelationship.StudentID = Students.StudentID INNER JOIN Staff ON StudentRelationship.StaffID = Staff.StaffID") # Cross-table SQL
    relationships = cursor.fetchall()
    data = []
    for row in relationships:
        cursor.execute("SELECT Firstname, LastName FROM Students WHERE StudentID=?"
                       , (row[0], )
                       ) # Parameterised SQL
        studentData = cursor.fetchone()
        cursor.execute("SELECT Firstname, LastName, Title FROM Staff WHERE StaffID=?"
                        , (row[1], )
                        ) # Parameterised SQL
        staffData = cursor.fetchone()
        relationshipTypes = {
            0: "other relationship",
            1: "teacher",
            2: "form tutor",
            3: "head of year"
        }
        data.append(f"{staffData[2]} {staffData[0]} {staffData[1]} is the {relationshipTypes[row[2]]} of {studentData[0]} {studentData[1]} ")
    
    connection.close()
    return render_template("all_student_staff_relationships.html", data=data)

@app.route('/app/users/students/Links/<string:studentID>', methods=['GET', 'POST'])
@login_required
def staff_student_relationships(studentID):
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("staff_student_relationships_lookup"))
    del studentID
    
    if request.method == 'POST':
        email = request.form.get('email-list')
        if not email:
            return redirect(url_for('staff_student_relationships_lookup'))
        return redirect(url_for('edit_staff_student_relationships', studentID=cleanedID, staffEmail=email))
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT Email FROM Staff WHERE AccountArchived='False';")
    result = cursor.fetchall()
    if result == None or len(result) == 0: # Error Handling
        print("No accounts found")
        connection.close()
        return render_template("staff_student_relationships.html", msg="empty")
    
    emails = []
    for email in result:
        emails.append(email[0])
    
    return render_template("staff_student_relationships.html", studentID=cleanedID, emails=emails)

@app.route('/app/users/students/Links/<string:studentID>/<string:staffEmail>', methods=['GET', 'POST'])
@login_required
def edit_staff_student_relationships(studentID, staffEmail):
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    cleanedID = entry_cleaner(studentID, "sql")
    if studentID != cleanedID: # Error Handling
        print("Invalid ID")
        return redirect(url_for("staff_student_relationships_lookup"))
    del studentID
    
    cleanedEmail = entry_cleaner(staffEmail, "sql")
    if staffEmail != cleanedEmail: # Error Handling
        print("Invalid ID")
        return redirect(url_for("staff_student_relationships_lookup"))
    del staffEmail
    
    if request.method == 'GET':
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()
        
        cursor.execute("SELECT FirstName, LastName, DateOfBirth FROM Students WHERE StudentID=?;"
                       , (cleanedID, )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Target user not found")
            return redirect(url_for("staff_student_relationships_lookup"))
        
        studentData = [
            f"{result[0]} {result[1]}",
            result[2]
        ]
        
        cursor.execute("SELECT StaffID, FirstName, LastName, Title, Email FROM Staff WHERE Email=? and AccountArchived='False';"
                       , (cleanedEmail, )
                       ) # Parameterised SQL
        result = cursor.fetchone()
        if result == None: # Error Handling
            connection.close()
            print("Target user not found")
            return redirect(url_for("staff_student_relationships_lookup"))
        
        staffDetails = f"{result[3]} {result[1]} {result[2]}: {result[4]}"
        
        cursor.execute("SELECT Relationship FROM StudentRelationship WHERE StudentID = ? AND StaffID = ?;"
                       , (cleanedID, result[0])
                       ) # Parameterised SQL
        result = cursor.fetchone()
        connection.close()
        
        if result == None: # Error Handling
            print("No relationship found")
            oldRelationship = "None"
        else:
            oldRelationship = str(result[0])
        
        return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="")
    
    newRelationship = request.form.get('relationship')
    
    if newRelationship in [1, 2, 3, 0, "1", "2", "3", "0"]:
        cleanedNewRelationship = int(newRelationship)
    elif newRelationship == "None":
        cleanedNewRelationship = "None"
    else:
        data = generate_data_for_student_link(cleanedID, cleanedEmail)
        import werkzeug.wrappers.response
        if type(data) == werkzeug.wrappers.response.Response:
            return data
        
        studentData, staffDetails, studentID, staffEmail, oldRelationship = data
        return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Invalid Relationship")
    del newRelationship

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT StaffID FROM Staff WHERE Email=? and AccountArchived='False';"
                   , (cleanedEmail, )
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        connection.close()
        print("Target user not found")
        return redirect(url_for("staff_student_relationships_lookup"))
    else:
        staffID = result[0]
    
    cursor.execute("SELECT RelationshipID, Relationship FROM StudentRelationship WHERE StudentID = ? AND StaffID = ?;"
                   , (cleanedID, staffID)
                   ) # Parameterised SQL
    result = cursor.fetchone()
    if result == None: # Error Handling
        print("No relationship found")
        oldRelationship = "None"
        result = [""]
    else:
        oldRelationship = result[1]
    
    if oldRelationship == cleanedNewRelationship:
        # No change in relationship
        print("No change")
        connection.close()
        
        data = generate_data_for_student_link(cleanedID, cleanedEmail)
        import werkzeug.wrappers.response
        if type(data) == werkzeug.wrappers.response.Response:
            return data
        
        studentData, staffDetails, studentID, staffEmail, oldRelationship = data
        return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="No change detected")
    
    elif oldRelationship != "None" and cleanedNewRelationship == "None":
        # Delete existing relationship
        if result[0] == "":
            connection.close()
            
            data = generate_data_for_student_link(cleanedID, cleanedEmail)
            import werkzeug.wrappers.response
            if type(data) == werkzeug.wrappers.response.Response:
                return data
            
            studentData, staffDetails, studentID, staffEmail, oldRelationship = data
            return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Unknown Error Occurred")
        cursor.execute("DELETE FROM StudentRelationship WHERE RelationshipID = ?;"
                       , (result[0], )
                       ) # Parameterised SQL
        connection.commit()
        connection.close()
        
        data = generate_data_for_student_link(cleanedID, cleanedEmail)
        import werkzeug.wrappers.response
        if type(data) == werkzeug.wrappers.response.Response:
            return data
        
        studentData, staffDetails, studentID, staffEmail, oldRelationship = data
        return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Link removed", entry="submit")
    
    elif oldRelationship != "None" and cleanedNewRelationship != "None":
        # Change existing relationship
        if result[0] == "":
            connection.close()
            
            data = generate_data_for_student_link(cleanedID, cleanedEmail)
            import werkzeug.wrappers.response
            if type(data) == werkzeug.wrappers.response.Response:
                return data
            
            studentData, staffDetails, studentID, staffEmail, oldRelationship = data
            
            return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Unknown Error Occurred")
        try:
            cursor.execute("UPDATE StudentRelationship SET StudentID = ?, StaffID = ?, Relationship = ? WHERE RelationshipID = ?"
                           , (
                               cleanedID,
                               staffID,
                               cleanedNewRelationship,
                               result[0]
                               )
                           ) # Parameterised SQL
            connection.commit()
        except sqlite3.IntegrityError: # Error Handling
            print("Failed CHECK constraint")
            connection.close()
            
            data = generate_data_for_student_link(cleanedID, cleanedEmail)
            import werkzeug.wrappers.response
            if type(data) == werkzeug.wrappers.response.Response:
                return data
            
            studentData, staffDetails, studentID, staffEmail, oldRelationship = data
            return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Unknown Error Occurred")
    
    elif oldRelationship == "None" and cleanedNewRelationship != "None":
        # Create new relationship
        try:
            cursor.execute("INSERT INTO StudentRelationship(StudentID, StaffID, Relationship) VALUES (?, ?, ?);"
                           , (
                               cleanedID,
                               staffID,
                               cleanedNewRelationship
                               )
                           ) # Parameterised SQL
            
            connection.commit()
        except sqlite3.IntegrityError: # Error Handling
            print("Failed CHECK constraint")
            connection.close()
            
            data = generate_data_for_student_link(cleanedID, cleanedEmail)
            import werkzeug.wrappers.response
            if type(data) == werkzeug.wrappers.response.Response:
                return data
            
            studentData, staffDetails, studentID, staffEmail, oldRelationship = data
            
            return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Link removed", entry="submit")
    
    else:
        # Should never get here?
        connection.close()
        
        data = generate_data_for_student_link(cleanedID, cleanedEmail)
        import werkzeug.wrappers.response
        if type(data) == werkzeug.wrappers.response.Response:
            return data
        
        studentData, staffDetails, studentID, staffEmail, oldRelationship = data
        return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Unknown Error Occurred")
    
    connection.close()
    
    data = generate_data_for_student_link(cleanedID, cleanedEmail)
    import werkzeug.wrappers.response
    if type(data) == werkzeug.wrappers.response.Response:
        return data
    
    studentData, staffDetails, studentID, staffEmail, oldRelationship = data
    return render_template("student_staff_relationship.html", studentData=studentData, staffDetails=staffDetails, studentID=cleanedID, staffEmail=cleanedEmail, relationship=oldRelationship, msg="Sucessfully updated", entry="submit")
# Objective 6 completed

@app.route('/app/settings', methods=['GET'])
@login_required
def app_settings():# TODO
    if not current_user.admin:
        return redirect(url_for('dashboard'))
    
    # return render_template("app_settings.html")
    return render_template("under_construction.html")

@app.route('/app/notifications', methods=['GET'])
@login_required
def notifications():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    
    cursor.execute("SELECT NotificationID, BannerMessage, URL, TimeStamp, Ephemeral FROM Notifications WHERE RecipientID=?;"
                   , (current_user.id, )
                   ) # Parameterised SQL
    result = cursor.fetchall()
    
    if result == None or len(result) == 0:
        print("No notifications found")
        connection.close()
        
        return Response(json.dumps([]), mimetype='application/json')
    
    data = []
    
    for notification in result:
        if float(notification[3]) >= float(datetime.timestamp(datetime.now())) or notification[4] == "True":
            data.append(
                    {
                        "message": notification[1],
                        "link": url_for('alerts_view', notificationID=notification[2])
                    }
                )
        else:
            cursor.execute("DELETE FROM Notifications WHERE NotificationID = ?;"
                           , (notification[0], )
                           ) # Parameterised SQL
            connection.commit()
    
    connection.close()
    return Response(json.dumps(data), mimetype='application/json')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if request.method == 'GET':
        return redirect(url_for('login'))
    return "True"


#########################################################################
#########################################################################
####################             Errors             #####################
#########################################################################
#########################################################################


def handle_not_found(error):
    if type(current_user._get_current_object()) is User:
        return render_template("404.html")
    return redirect(url_for('login'))

def handle_no_permission(error):
    if type(current_user._get_current_object()) is User:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


#########################################################################
#########################################################################
####################             Launch             #####################
#########################################################################
#########################################################################


if __name__ == '__main__':
    app.register_error_handler(404, handle_not_found)
    app.register_error_handler(401, handle_no_permission)
    app.run(debug=True, host='0.0.0.0')