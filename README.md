# Secure messaging
 My A-Level Computer Science NEA

My project is a secure messaging system that schools could use to communicate with staff members.

### Features I would like to include are:
- Staff-to-staff messaging – Private messaging between staff and file exchanging

- Staff-to-group messaging – Staff can send notices to groups of people.

- Alert – Staff can send a notification to all staff who should receive the alert. This message should appear on the home page for each of the notified staff members so that it is easy to see.

- Secure reporting – Staff can securely record conversations, concerns, and information about students. These records can only be seen by members of SENCo and safeguarding.

- Student notify – Sending a message to all appropriate people for a student (Head of year, tutor, teachers for the day, etc.).

- Multi-factor authentication

- Full system control for admin accounts – The ability to track logins, enable/disable features, force multi-factor sign-on, etc.

The system should be run locally with ideally no access to the internet so that it is more secure. Although this means that staff cannot use the system from home, it also stops hackers from attacking it.

## Objectives

1.	Encryption of student reports (Secure reporting)
2.	Account system
3.	Sending messages
4.	Uploading attachments
5.	Admin page
6.	Linking teachers to students (for Student notify)
7.	Search up student’s records for safeguarding and SENCo staff
8.  Read receipts
9.  Session timeout

> ### Tip!
>
> When an objective is complete a comment will be made surrounding the block of code that fulfilled the objective.
>
> See examples below:
>
> Start of objective comment: 
> ```python
> # Objective {Number} started
> ```
> End of objective comment:
> ```python
> # Objective {Number} completed
> ```

## Progress

| Objective | Progress | Comment | Commit first introduced |
|:---------:|:--------:|:--------|:-----------------------:|
| 1         | ❌       | -       | N/A                     |
| 2         | ❌       | -       | N/A                     |
| 3         | ❌       | -       | N/A                     |
| 4         | ❌       | -       | N/A                     |
| 5         | ❌       | -       | N/A                     |
| 6         | ❌       | -       | N/A                     |
| 7         | ❌       | -       | N/A                     |
| 8         | ❌       | -       | N/A                     |
| 9         | ❌       | -       | N/A                     |

---

## Database Schema

### Staff
| Column          | Description                                     | Example | Type    | Primary Key | Foreign Key | Constraints       |
|-----------------|-------------------------------------------------|---------|---------|:-----------:|:-----------:|:-----------------:|
| StaffID         | The integer id associated with the staff member | 1       | Integer | ✅          | -           | -                 |
| FirstName       | The staff member's first name                   | John    | Text    | ❌          | -           | -                 |
| LastName        | The staff member's last name                    | Smith   | Text    | ❌          | -           | -                 |
| Title           | The staff member's title                        | Mr      | Text    | ❌          | -           | -                 |
| AccountEnabled  | Whether the staff member can login              | True    | Boolean | ❌          | -           | 'True' or 'False' |
| AccountArchived | Whether the staff member "Exists"               | False   | Boolean | ❌          | -           | 'True' or 'False' |

###  Roles
| Column       | Description                                        | Example | Type    | Primary Key | Foreign Key    | Constraints       |
|--------------|----------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|:-----------------:|
| StaffID      | The integer id associated with the staff member    | 1       | Integer | ✅          | Staff(StaffID) | -                 |
| SENCo        | Whether they are a member of the SENCo team        | False   | Boolean | ❌          | -              | 'True' or 'False' |
| Safeguarding | Whether they are a member of the safeguarding team | False   | Boolean | ❌          | -              | 'True' or 'False' |
| Admin        | Whether the staff member have admin access         | False   | Boolean | ❌          | -              | 'True' or 'False' |

###  Login
| Column   | Description                                     | Example | Type    | Primary Key | Foreign Key    |
|----------|-------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|
| StaffID  | The integer id associated with the staff member | 1       | Integer | ✅          | Staff(StaffID) |
| PassHash | The hashed password                             | -       | Blob    | ❌          | -              |
| PassSalt | The random salt used to hash the password       | -       | Blob    | ❌          | -              |

### Messages
| Column       | Description                                                           | Example | Type    | Primary Key | Foreign Key    | Constraints       |
|--------------|-----------------------------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|:-----------------:|
| MessageID    | The integer id associated with the message                            | 1       | Integer | ✅          | -              | -                 |
| SenderID     | The integer id associated with the staff member sending the message   | 1       | Integer | ❌          | Staff(StaffID) | -                 |
| RecipientID  | The integer id associated with the staff member receiving the message | 1       | Integer | ❌          | Staff(StaffID) | -                 |
| Message      | The encrypted message                                                 | -       | Blob    | ❌          | -              | -                 |
| TimeStamp    | The timestamp that the message was sent                               | -       | Blob    | ❌          | -              | -                 |
| ReadReceipts | Whether the message has been read                                     | False   | Text    | ❌          | -              | 'True' or 'False' |

### Students
| Column       | Description                                | Example | Type    | Primary Key | Foreign Key    |
|--------------|--------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|
| StudentID    | The integer id associated with the student | 1       | Integer | ✅          | -              |
| FirstName    | The encrypted first name of the student    | John    | Text    | ❌          | -              |
| LastName     | The encrypted last name of the student     | Smith   | Text    | ❌          | -              |
| TutorID      | The id of the student's form tutor         | 1       | Integer | ❌          | Staff(StaffID) |
| HeadOfYearID | The id of the student's head of year       | 1       | Integer | ❌          | Staff(StaffID) |

### Reporting
| Column       | Description                                                          | Example | Type    | Primary Key | Foreign Key         |
|--------------|----------------------------------------------------------------------|:-------:|:-------:|:-----------:|:-------------------:|
| ReportID     | The integer id associated with the report                            | 1       | Integer | ✅          | -                   |
| StudentID    | The integer id associated with the student who is being reported     | 1       | Integer | ❌          | Students(StudentID) |
| StaffID      | The integer id associated with the staff member who filed the report | 1       | Integer | ❌          | Staff(StaffID)      |
| Report       | The encrypted report                                                 | -       | Blob    | ❌          | -                   |
| Timestamp    | The timestamp that the report was filed                              | -       | Blob    | ❌          | -                   |

### Files
| Column   | Description                                                       | Example | Type    | Primary Key | Foreign Key    |
|----------|-------------------------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|
| FileID   | The integer id associated with the file                           | 1       | Integer | ✅          | -              |
| OwnerID  | The integer id associated with the staff member who owns the file | 1       | Integer | ❌          | Staff(StaffID) |
| FilePath | The path on the server to the file                                | -       | Text    | ❌          | -              |
| FileHash | The hash of the file (For integrity checks)                       | -       | Blob    | ❌          | -              |
