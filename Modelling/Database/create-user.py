import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

#Example Values
firstName = "John"
lastName = "Smith"
title = "Mr"
enabled = "False"
SENCo = True
safeguarding = False
admin = False
passwordHash = "Averysecurepasswordthathasbeenhashed".encode() # Will be passed in already encoded
passwordSalt = "Arandomstringofcharacters".encode() # Will be passed in already encoded

"""Staff table columns:
    StaffID (integer): The integer id associated with the staff member. Example: 1
    FirstName (string): The staff member's first name. Example: John
    LastName (string): The staff member's last name. Example: Smith
    Title (string): The staff member's title. Example: Mr
    AccountEnabled (bool): Whether the staff member can login, True = Can login, False = Can't login. Example: True
    AccountArchived (bool): Whether the staff member "exists", True = , False = Can't login. Example: False
"""     
"""Roles table columns:
    StaffID (integer): The integer id associated with the staff member. Example: 1
    SENCo (bool): Whether the staff member is a member of the SENco team. Example: False
    Safeguarding (bool): Whether the staff member is a member of the safeguarding team. Example: False
    Admin (bool): Whether the staff member has administator access to the program. Example: False
"""     
"""Login table columns:(StaffID, PassHash, PassSalt)
    StaffID (integer): The integer id associated with the staff member. Example: 1
    PassHash (blob): The staff member's password hash. Example: John
    PassSalt (blob): The staff member's password hash salt. Example: Smith
"""     
#

try:
    cur.execute(f"""INSERT INTO Staff (FirstName, LastName, Title, AccountEnabled, AccountArchived)
                VALUES ('{firstName}', '{lastName}', '{title}', '{enabled}', 'False');""")
    conn.commit()
except sqlite3.IntegrityError:
    print("Failed CHECK constraint")

cur.execute(f"""SELECT StaffID FROM Staff WHERE FirstName='{firstName}' and LastName='{lastName}' and Title='{title}' and AccountEnabled='{enabled}'""")
results = cur.fetchall()

if len(results) > 1:
    print("Too many other entries, take largest")
    staffID = results[len(results)-1][0]
elif len(results) == 1:
    staffID = results[0][0]
elif len(results) == 0:
    raise "Error: Staff doesn't exist"

try:
    cur.execute(f"""INSERT INTO Roles (StaffID, SENCo, Safeguarding, Admin)
                VALUES ('{staffID}','{SENCo}','{safeguarding}', '{admin}');""")
    conn.commit()
except sqlite3.IntegrityError:
    print("Failed CHECK constraint")

try:
    cur.execute(f"""INSERT INTO Login (StaffID, PassHash, PassSalt)
                VALUES ('{staffID}', '{passwordHash.decode()}', '{passwordSalt.decode()}');""")
    conn.commit()
except sqlite3.IntegrityError:
    print("Failed CHECK constraint")

conn.close()