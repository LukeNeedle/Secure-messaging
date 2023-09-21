import sqlite3
def create_user(firstName:str, lastName:str, title:str, email:str,
                enabled:bool, SENCo:bool, safeguarding:bool, admin:bool,
                passwordHash, passwordSalt):
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
                    VALUES ('{firstName}', '{lastName}', '{title}', '{email}', '{enabled}', 'False', '{passwordHash.decode()}', '{passwordSalt.decode()}', '{SENCo}', '{safeguarding}', '{admin}');""")
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

create_user(firstName="John", lastName="Smith", title="Mr", email = "JS@school.uk",
            enabled = "False", SENCo = True, safeguarding = False, admin = False,
            passwordHash = "Averysecurepasswordthathasbeenhashed".encode(),
            passwordSalt = "Arandomstringofcharacters".encode())
