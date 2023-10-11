from flask_login import UserMixin
import sqlite3

class User(UserMixin):
    def __init__(self, userDetails:dict):
        self.id = userDetails['id']
        self.title = userDetails['title']
        self.fname = userDetails['firstName']
        self.lname = userDetails['lastName']
        self.email = userDetails['email']
        self.enabled = userDetails['accountEnabled']
        self.archived = userDetails['accountArchived']
        self.passwordHash = userDetails['passhash']
        self.passwordSalt = userDetails['passsalt']
        self.senco = userDetails['SENCo']
        self.safeguarding = userDetails['safeguarding']
        self.admin = userDetails['admin']

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