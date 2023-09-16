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
#

try:
    cur.execute(f"""INSERT INTO Staff(FirstName, LastName, Title, AccountEnabled, AccountArchived, PassHash, PassSalt, SENCo, Safeguarding, Admin)
                VALUES ('{firstName}', '{lastName}', '{title}', '{enabled}', 'False', '{passwordHash.decode()}', '{passwordSalt.decode()}', '{SENCo}', '{safeguarding}', '{admin}');""")
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
    raise "Error: Staff doesn't exist"


conn.close()