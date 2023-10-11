import database
import hash_function

database.create_tables()

database.create_user(firstName="John", lastName="Smith", title="Mr", email = "js@school.uk",
            enabled = "False", SENCo = True, safeguarding = False, admin = False,
            passwordHash = hash_function.hash_variable("Averysecurepasswordthathasbeenhashed", "Arandomstringofcharacters"),
            passwordSalt = "Arandomstringofcharacters")
