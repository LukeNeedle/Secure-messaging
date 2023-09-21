from flask_login import UserMixin
import sqlite3

class User(UserMixin):
    def __init__(self, id, title, firstName, lastName, accountEnabled, accountArchived, password, passhash, SENCo, safeguarding, admin):
        self.id = id
        self.title = title
        self.fname = firstName
        self.lname = lastName
        self.enabled = accountEnabled
        self.archived = accountArchived
        self.password = password
        self.passhash = passhash
        self.senco = SENCo
        self.safeguarding = safeguarding
        self.admin = admin

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
            user = User(userDetails['id'], userDetails['title'], userDetails['firstName'], userDetails['lastName'], userDetails['accountEnabled'], userDetails['accountArchived'], userDetails['password'], userDetails['passhash'], userDetails['SENCo'], userDetails['safeguarding'], userDetails['admin'])
            connection.close()
            return user