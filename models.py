from flask_login import UserMixin
import sqlite3

class User(UserMixin):
    def __init__(self, userDetails:dict):
        self.id = int(userDetails['id'])
        self.title = userDetails['title']
        self.fname = userDetails['firstName']
        self.lname = userDetails['lastName']
        self.email = userDetails['email']

        if userDetails['accountEnabled'] == "True":
            self.enabled = True
        else:
            self.enabled = False

        if userDetails['accountArchived'] == "True":
            self.archived = True
        else:
            self.archived = False

        self.passwordHash = userDetails['passhash']
        self.passwordSalt = userDetails['passsalt']

        if userDetails['SENCo'] == "True":
            self.senco = True
        else:
            self.senco = False

        if userDetails['safeguarding'] == "True":
            self.safeguarding = True
        else:
            self.safeguarding = False

        if userDetails['admin'] == "True":
            self.admin = True
        else:
            self.admin = False

    def is_authenticated(self):
        if self.id:
            return True
        else:
            return False

    def is_active(self):
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute(f"""SELECT AccountEnabled FROM Staff WHERE StaffID='{self.id}';""")
        result = cursor.fetchone()
        if result == None:
            # User doesn't exist
            return False
        elif result[0] == "True":
            return False
        else:
            return True

    def is_anonymous(self):
        return False
    
    def get_user(userID):
        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute(f"""SELECT * FROM Staff WHERE StaffID='{userID}';""")
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
            user = User(userDetails)
            connection.close()
            return user