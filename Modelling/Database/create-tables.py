import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS "Staff" (
	"StaffID"	INTEGER NOT NULL UNIQUE,
	"FirstName"	TEXT NOT NULL,
	"LastName"	TEXT NOT NULL,
	"Title"	TEXT NOT NULL,
	"LastLogin"	TEXT,
	"AccountEnabled"	TEXT NOT NULL DEFAULT 'False',
	"AccountArchived"	TEXT NOT NULL DEFAULT 'False',
	PRIMARY KEY("StaffID" AUTOINCREMENT),
	CHECK ("AccountEnabled"=='True' OR "AccountEnabled"=='False'),
	CHECK ("AccountArchived"=='True' OR "AccountArchived"=='False')
)""")
conn.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS "Login" (
	"StaffID"	INTEGER NOT NULL UNIQUE,
	"PassHash"	BLOB NOT NULL UNIQUE,
	"PassSalt"	BLOB NOT NULL UNIQUE,
	PRIMARY KEY("StaffID"),
	FOREIGN KEY("StaffID") REFERENCES "Staff"("StaffID")
)""")
conn.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS "Roles" (
	"StaffID"	INTEGER NOT NULL UNIQUE,
	"SENCo"	TEXT NOT NULL DEFAULT 'False',
	"Safeguarding"	TEXT NOT NULL DEFAULT 'False',
	"Admin"	TEXT NOT NULL DEFAULT 'False',
	PRIMARY KEY("StaffID"),
	FOREIGN KEY("StaffID") REFERENCES "Staff"("StaffID"),
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
	"TimeStamp"	BLOB NOT NULL,
	"ReadReceipts" TEXT NOT NULL DEFAULT 'False',
	FOREIGN KEY("SenderID") REFERENCES "Staff"("StaffID"),
	FOREIGN KEY("RecipientID") REFERENCES "Staff"("StaffID"),
	PRIMARY KEY("MessageID" AUTOINCREMENT),
	CHECK ("ReadReceipts"=='True' OR "ReadReceipts"=='False')
)""")
conn.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS "Students" (
	"StudentID"	INTEGER NOT NULL UNIQUE,
	"FirstName" STRING NOT NULL,
	"LastName"  STRING NOT NULL,
	"TutorID"	INTEGER,
	"HeadOfYearID"	INTEGER,
	FOREIGN KEY("HeadOfYearID") REFERENCES "Staff"("StaffID"),
	FOREIGN KEY("TutorID") REFERENCES "Staff"("StaffID"),
	PRIMARY KEY("StudentID" AUTOINCREMENT)
)""")
conn.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS "Reporting" (
	"ReportID"	INTEGER NOT NULL UNIQUE,
	"StudentID"	INTEGER NOT NULL,
	"StaffID"	INTEGER NOT NULL,
	"Report"	BLOB NOT NULL,
	"Timestamp"	TEXT NOT NULL,
	PRIMARY KEY("ReportID" AUTOINCREMENT),
	FOREIGN KEY("StudentID") REFERENCES "Students"("StudentID"),
	FOREIGN KEY("StaffID") REFERENCES "Staff"("StaffID"))
""")
conn.commit()

cur.execute("""CREATE TABLE IF NOT EXISTS "Files" (
	"FileID"	INTEGER NOT NULL UNIQUE,
	"OwnerID"	INTEGER NOT NULL UNIQUE,
	"FilePath"	BLOB NOT NULL UNIQUE,
	"FileHash"	BLOB NOT NULL,
	FOREIGN KEY("OwnerID") REFERENCES "Staff"("StaffID"),
	PRIMARY KEY("FileID" AUTOINCREMENT)
)""")
conn.commit()

conn.close()