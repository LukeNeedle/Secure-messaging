class User():
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
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False
    
    def get_id(self):
        return self.id