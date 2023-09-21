import database

database.create_tables()

database.create_user(firstName="John", lastName="Smith", title="Mr", email = "JS@school.uk",
            enabled = "False", SENCo = True, safeguarding = False, admin = False,
            passwordHash = "Averysecurepasswordthathasbeenhashed".encode(),
            passwordSalt = "Arandomstringofcharacters".encode())
