import database
import hash_function

database.create_tables()

database.create_user(
    firstName="Agnes",
    lastName="Hicks",
    title="Mrs",
    email = "ah@school.uk",
    enabled = True,
    SENCo = True,
    safeguarding = False,
    admin = False,
    passwordHash = hash_function.hash_variable("password", "KjszcONx3"),
    passwordSalt = "KjszcONx3"
    )

database.create_user(
    firstName="Vera",
    lastName="Martinez",
    title="Mrs",
    email = "vm@school.uk",
    enabled = True,
    SENCo = False,
    safeguarding = False,
    admin = False,
    passwordHash = hash_function.hash_variable("password", "g0CQvirAQcu4h82eZ"),
    passwordSalt = "g0CQvirAQcu4h82eZ"
    )

database.create_user(
    firstName="Callie",
    lastName="Watkins",
    title="Mrs",
    email = "cw@school.uk",
    enabled = True,
    SENCo = False,
    safeguarding = False,
    admin = False,
    passwordHash = hash_function.hash_variable("password", "u1Dyfr4aXphDQ"),
    passwordSalt = "u1Dyfr4aXphDQ"
    )

database.create_user(
    firstName="Dennis",
    lastName="Roy",
    title="Mr",
    email = "dr@school.uk",
    enabled = True,
    SENCo = False,
    safeguarding = True,
    admin = False,
    passwordHash = hash_function.hash_variable("password", "Hn68KRU3mfA5v"),
    passwordSalt = "Hn68KRU3mfA5v"
    )

database.create_user(
    firstName="Clyde",
    lastName="Wright",
    title="Mr",
    email = "admin@school.uk",
    enabled = True,
    SENCo = False,
    safeguarding = False,
    admin = True,
    passwordHash = hash_function.hash_variable("password", "xwzflt68c3F0m5qS"),
    passwordSalt = "xwzflt68c3F0m5qS"
    )
