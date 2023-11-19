import sqlite3
def create_tables():
	"""
	Creates the database "database.db" and creates the tables for it. Doesn't return anything.
	"""
	conn = sqlite3.connect("database.db")
	cur = conn.cursor()

	cur.execute("""CREATE TABLE IF NOT EXISTS "Staff" (
		"StaffID"	INTEGER NOT NULL UNIQUE,
		"FirstName"	TEXT NOT NULL,
		"LastName"	TEXT NOT NULL,
		"Title"	TEXT NOT NULL,
		"Email" TEXT NOT NULL UNIQUE,
		"AccountEnabled"	TEXT NOT NULL DEFAULT 'False',
		"AccountArchived"	TEXT NOT NULL DEFAULT 'False',
		"PassHash"	BLOB NOT NULL UNIQUE,
		"PassSalt"	TEXT NOT NULL UNIQUE,
		"SENCo"	TEXT NOT NULL DEFAULT 'False',
		"Safeguarding"	TEXT NOT NULL DEFAULT 'False',
		"Admin"	TEXT NOT NULL DEFAULT 'False',
		PRIMARY KEY("StaffID" AUTOINCREMENT),
		CHECK ("AccountEnabled"=='True' OR "AccountEnabled"=='False'),
		CHECK ("AccountArchived"=='True' OR "AccountArchived"=='False'),
		CHECK ("SENCo"=='True' OR "SENCo"=='False'),
		CHECK ("Safeguarding"=='True' OR "Safeguarding"=='False'),
		CHECK ("Admin"=='True' OR "Admin"=='False')
	)""")
	conn.commit()

	cur.execute("""CREATE TABLE IF NOT EXISTS "Messages" (
		"MessageID"	INTEGER NOT NULL UNIQUE,
		"SenderID"	INTEGER NOT NULL,
		"RecipientID"	INTEGER NOT NULL,
		"Message"	BLOB NOT NULL,
		"HashedUrl"	TEXT NOT NULL UNIQUE,
		"TimeStamp"	TEXT NOT NULL,
		"ReadReceipts" TEXT NOT NULL DEFAULT 'False',
		"Archived" TEXT NOT NULL DEFAULT 'False',
        "Key"	TEXT NOT NULL,
		FOREIGN KEY("SenderID") REFERENCES "Staff"("StaffID"),
		FOREIGN KEY("RecipientID") REFERENCES "Staff"("StaffID"),
		PRIMARY KEY("MessageID" AUTOINCREMENT),
		CHECK ("ReadReceipts"=='True' OR "ReadReceipts"=='False'),
		CHECK ("Archived"=='True' OR "Archived"=='False')
	)""")
	conn.commit()

	cur.execute("""CREATE TABLE IF NOT EXISTS "Students" (
		"StudentID"	INTEGER NOT NULL UNIQUE,
		"FirstName" STRING NOT NULL,
		"LastName"  STRING NOT NULL,
		PRIMARY KEY("StudentID" AUTOINCREMENT)
	)""")
	conn.commit()

	cur.execute("""CREATE TABLE IF NOT EXISTS "StudentRelationship" (
		"RelationshipID"	INTEGER NOT NULL UNIQUE,
		"StudentID" STRING NOT NULL,
		"StaffID"  STRING NOT NULL,
		"Relationship"	INT NOT NULL,
		FOREIGN KEY("StudentID") REFERENCES "Students"("StudentID"),
		FOREIGN KEY("StaffID") REFERENCES "Staff"("StaffID"),
		CHECK ("Relationship"==1 OR "Relationship"==2 OR "Relationship"==3),
		PRIMARY KEY("RelationshipID" AUTOINCREMENT)
	)""")
	conn.commit()

	cur.execute("""CREATE TABLE IF NOT EXISTS "Reporting" (
		"ReportID"	INTEGER NOT NULL UNIQUE,
		"StudentID"	INTEGER NOT NULL,
		"StaffID"	INTEGER NOT NULL,
		"Report"	BLOB NOT NULL,
		"TimeStamp"	TEXT NOT NULL,
		PRIMARY KEY("ReportID" AUTOINCREMENT),
		FOREIGN KEY("StudentID") REFERENCES "Students"("StudentID"),
		FOREIGN KEY("StaffID") REFERENCES "Staff"("StaffID")
	)""")
	conn.commit()

	cur.execute("""CREATE TABLE IF NOT EXISTS "Files" (
		"FileID"	INTEGER NOT NULL UNIQUE,
		"OwnerID"	INTEGER NOT NULL,
		"Origin"	TEXT NOT NULL,
		"FilePath"	BLOB NOT NULL UNIQUE,
		"HashedUrl"	TEXT NOT NULL UNIQUE,
		"TimeStamp"	TEXT NOT NULL,
		FOREIGN KEY("OwnerID") REFERENCES "Staff"("StaffID"),
		PRIMARY KEY("FileID" AUTOINCREMENT)
	)""")
	conn.commit()

	conn.close()

def create_user(firstName:str, lastName:str, title:str, email:str,
                enabled:bool, SENCo:bool, safeguarding:bool, admin:bool,
                passwordHash, passwordSalt:str):
    """
    Creates the user from the data provided. Doesn't return anything.

    Args:
        firstName (str): The staff member's first name
        lastName (str): The staff member's last name
        title (str): The staff member's title
        email (str): The staff member's email
        enabled (bool): Whether the staff member can login
        SENCo (bool): Whether they are a member of the SENCo team
        safeguarding (bool): Whether they are a member of the safeguarding team
        admin (bool): Whether the staff member have admin access
        passwordHash (blob): The hashed password
        passwordSalt (blob): The random salt used to hash the password
    """
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    try:
        cur.execute(f"""INSERT INTO Staff(FirstName, LastName, Title, Email, AccountEnabled, AccountArchived, PassHash, PassSalt, SENCo, Safeguarding, Admin)
                    VALUES ('{firstName}', '{lastName}', '{title}', '{email}', '{enabled}', 'False', '{passwordHash}', '{passwordSalt}', '{SENCo}', '{safeguarding}', '{admin}');""")
        conn.commit()
    except sqlite3.IntegrityError:
        print("Failed CHECK constraint")

    cur.execute(f"""SELECT StaffID FROM Staff WHERE FirstName='{firstName}' and LastName='{lastName}' and Title='{title}' and AccountEnabled='{enabled}' and SENCo='{SENCo}' and Safeguarding='{safeguarding}' and Admin='{admin}'""")
    results = cur.fetchall()

    if len(results) > 1:
        print("Too many other entries, take largest")
        staffID = results[len(results)-1][0]
    elif len(results) == 1:
        staffID = results[0][0]
    elif len(results) == 0:
        conn.close()
        raise "Error: Staff member doesn't exist"

    conn.close()
    return staffID
