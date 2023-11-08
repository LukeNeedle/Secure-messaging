import database
import hash_function

database.create_tables()

database.create_user(firstName="John", lastName="Smith", title="Mr", email = "js@school.uk",
            enabled = True, SENCo = True, safeguarding = False, admin = False,
            passwordHash = hash_function.hash_variable("Averysecurepasswordthathasbeenhashed", "Arandomstringofcharacters"),
            passwordSalt = "Arandomstringofcharacters")
database.create_user(firstName="A", lastName="Admin", title="Mr", email = "admin@school.uk",
            enabled = True, SENCo = False, safeguarding = False, admin = True,
            passwordHash = hash_function.hash_variable("password", "SALT"),
            passwordSalt = "SALT")
