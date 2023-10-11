import database

database.create_tables()

database.create_user(firstName="John", lastName="Smith", title="Mr", email = "js@school.uk",
            enabled = "False", SENCo = True, safeguarding = False, admin = False,
            passwordHash = "Averysecurepasswordthathasbeenhashed",
            passwordSalt = "Arandomstringofcharacters")
