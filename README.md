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
6.	Linking teachers to students
7.	Search up student’s records for safeguarding and SENCo staff
8.  Read receipts
9.  Session timeout

These objectives aren't in any particular order and they are only numbered to help identify them inside the code.

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

| Objective | Progress | Comment                                                                                                    | Commit first introduced                                                                                   |
|:---------:|:--------:|:-----------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------:|
| 1         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [b49ea92](https://github.com/LukeNeedle/Secure-messaging/commit/b49ea9256456204bc1608bd0868fbb019534b39c) |
| 2         | ✅       | [Modelling/Basic Login/](https://github.com/LukeNeedle/Secure-messaging/tree/main/Modelling/Basic%20Login) | [df3d9ce](https://github.com/LukeNeedle/Secure-messaging/commit/df3d9ce0dbb5c0954efdaba7233797b99ce3a78f) |
| 3         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [0448463](https://github.com/LukeNeedle/Secure-messaging/commit/04484630959e990e1159af90ee10df15ce2747bd) |
| 4         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [8b4c5d4](https://github.com/LukeNeedle/Secure-messaging/commit/8b4c5d4920223af4fa88431a0fcd96a18dacf902) |
| 5         | ❌       | - |N/A|
| 6         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [30fa8ae](https://github.com/LukeNeedle/Secure-messaging/commit/30fa8ae584c2715a0ed4c792e128fae6553c832f) |
| 7         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [50a400b](https://github.com/LukeNeedle/Secure-messaging/commit/50a400bcb258e1f478bbed5007515f2cdebc93d4) |
| 8         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [220aa5a](https://github.com/LukeNeedle/Secure-messaging/commit/220aa5a7a418e1ebbb15a29d9f6f4448cea740c1) |
| 9         | ✅       | [app.py](https://github.com/LukeNeedle/Secure-messaging/blob/main/Modelling/Basic%20Login/app.py)          | [7f9785d](https://github.com/LukeNeedle/Secure-messaging/commit/7f9785df015104873e42c42ded1b56e80355b250) |

---

## Database Schema

### Staff
| Column          | Description                                        | Example      | Type    | Primary Key | Foreign Key    | Constraints                 |
|-----------------|----------------------------------------------------|--------------|---------|:-----------:|:--------------:|:---------------------------:|
| StaffID         | The integer ID associated with the staff member    | 1            | Integer | ✅          | -              | Not null, Unique            |
| FirstName       | The staff member's first name                      | John         | Text    | ❌          | -              | Not null                    |
| LastName        | The staff member's last name                       | Smith        | Text    | ❌          | -              | Not null                    |
| Title           | The staff member's title                           | Mr           | Text    | ❌          | -              | Not null                    |
| Email           | The staff member's email address                   | JS@school.uk | Text    | ❌          | -              | Not null, Unique            |
| AccountEnabled  | Whether the staff member can login                 | True         | Text    | ❌          | -              | 'True' or 'False', Not null |
| AccountArchived | Whether the staff member "Exists"                  | False        | Text    | ❌          | -              | 'True' or 'False', Not null |
| PassHash        | The hashed password                                | -            | Blob    | ❌          | -              | Not null, Unique            |
| PassSalt        | The random salt used to hash the password          | -            | Text    | ❌          | -              | Not null, Unique            |
| SENCo           | Whether they are a member of the SENCo team        | False        | Text    | ❌          | -              | 'True' or 'False', Not null |
| Safeguarding    | Whether they are a member of the safeguarding team | False        | Text    | ❌          | -              | 'True' or 'False', Not null |
| Admin           | Whether the staff member have admin access         | False        | Text    | ❌          | -              | 'True' or 'False', Not null |

### Messages
| Column       | Description                                                           | Example | Type    | Primary Key | Foreign Key    | Constraints                 |
|--------------|-----------------------------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|:---------------------------:|
| MessageID    | The integer ID associated with the message                            | 1       | Integer | ✅          | -              | Not null, Unique            |
| SenderID     | The integer ID associated with the staff member sending the message   | 1       | Integer | ❌          | Staff(StaffID) | Not null                    |
| RecipientID  | The integer ID associated with the staff member receiving the message | 1       | Integer | ❌          | Staff(StaffID) | Not null                    |
| Message      | The encrypted message                                                 | -       | Blob    | ❌          | -              | Not null                    |
| HashedUrl    | The hashed URL for the message                                        | -       | Text    | ❌          | -              | Not null, Unique            |
| TimeStamp    | The timestamp that the message was sent                               | -       | Text    | ❌          | -              | Not null                    |
| ReadReceipts | Whether the message has been read                                     | False   | Text    | ❌          | -              | 'True' or 'False', Not null |
| Archived     | Whether the message has been archived                                 | False   | Text    | ❌          | -              | 'True' or 'False', Not null |
| Key          | The encrypted key to decrypt the message                              | -       | Text    | ❌          | -              | Not null                    |

### Students
| Column       | Description                                | Example    | Type    | Primary Key | Foreign Key    | Constraints      |
|--------------|--------------------------------------------|:----------:|:-------:|:-----------:|:--------------:|:----------------:|
| StudentID    | The integer ID associated with the student | 1          | Integer | ✅          | -              | Not null, Unique |
| FirstName    | The encrypted first name of the student    | John       | Text    | ❌          | -              | Not null         |
| LastName     | The encrypted last name of the student     | Smith      | Text    | ❌          | -              | Not null         |
| DateOfBirth  | The date of birth of the student           | 2023-11-24 | Text    | ❌          | -              | Not null         |

### StudentRelationship
| Column         | Description                                                              | Example | Type    | Primary Key | Foreign Key         | Constraints      |
|----------------|--------------------------------------------------------------------------|:-------:|:-------:|:-----------:|:-------------------:|:----------------:|
| RelationshipID | The integer ID associated with the relationship                          | 1       | Integer | ✅          | -                   | Not null, Unique |
| StudentID      | The integer ID associated with the student                               | 1       | Integer | ❌          | Students(StudentID) | Not null         |
| StaffID        | The integer ID associated with the staff member                          | 1       | Integer | ❌          | Staff(StaffID)      | Not null         |
| Relationship   | The type of relationship: 1=teacher, 2=tutor, 3=head of year and 0=other | 1       | Integer  | ❌          | -                   | Not null         |

### Reporting
| Column       | Description                                                          | Example | Type    | Primary Key | Foreign Key         | Constraints      |
|--------------|----------------------------------------------------------------------|:-------:|:-------:|:-----------:|:-------------------:|:----------------:|
| ReportID     | The integer ID associated with the report                            | 1       | Integer | ✅          | -                   | Not null, Unique |
| StudentID    | The integer ID associated with the student who is being reported     | 1       | Integer | ❌          | Students(StudentID) | Not null         |
| StaffID      | The integer ID associated with the staff member who filed the report | 1       | Integer | ❌          | Staff(StaffID)      | Not null         |
| Report       | The encrypted report                                                 | -       | Blob    | ❌          | -                   | Not null         |
| URL          | The hashed URL for the message                                       | -       | Text    | ❌          | -                   | Not null         |
| TimeStamp    | The timestamp that the report was filed                              | -       | Text    | ❌          | -                   | Not null         |
| Key          | The encrypted key to decrypt the report                              | -       | Text    | ❌          | -                   | Not null         |

### Files
| Column    | Description                                                       | Example | Type    | Primary Key | Foreign Key    | Constraints      |
|-----------|-------------------------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|:----------------:|
| FileID    | The integer ID associated with the file                           | 1       | Integer | ✅          | -              | Not null, Unique |
| OwnerID   | The integer ID associated with the staff member who owns the file | 1       | Integer | ❌          | Staff(StaffID) | Not null         |
| Origin    | The message or report that the file is attached to                | m+1     | Text    | ❌          | -              | Not null         |
| FilePath  | The path on the server to the file                                | -       | Text    | ❌          | -              | Not null, Unique |
| HashedUrl | The uuid of FileID to be used to download the file                | -       | Text    | ❌          | -              | Not null, Unique |
| TimeStamp | The timestamp that the file was uploaded                          | -       | Text    | ❌          | -              | Not null         |

### Notifications
| Column         | Description                                                                  | Example | Type    | Primary Key | Foreign Key    | Constraints                 |
|----------------|------------------------------------------------------------------------------|:-------:|:-------:|:-----------:|:--------------:|:---------------------------:|
| NotificationID | The integer ID associated with the notification                              | 1       | Integer | ✅          | -              | Not null, Unique            |
| SenderID       | The integer ID associated with the staff member who sent the notification    | 1       | Integer | ❌          | Staff(StaffID) | Not null                    |
| RecipientID    | The integer ID associated with the staff member who can see the notification | 1       | Integer | ❌          | Staff(StaffID) | Not null                    |
| BannerMessage  | The short message that is displayed in the notification                      | Test    | Text    | ❌          | -              | Not null                    |
| Message        | The full notification contents                                               | Testing | Text    | ❌          | -              | Not null                    |
| URL            | A random UUID to view the full notification                                  | -       | Text    | ❌          | -              | Not null, Unique            |
| TimeStamp      | The timestamp that the notification will be deleted                          | -       | Text    | ❌          | -              | Not null                    |
| Ephemeral      | Whether the notification disappears on view                                   | True    | Text    | ❌          | -              | 'True' or 'False', Not null |


## Naming schema
|           | Correct name       |
|:---------:|:------------------:|
| Variables | firstSecondThird   |
| Files     | first_second_third |
| Functions | first_second_third |

Function documentation in code follows the google standard:
```python
"""
_summary_

Args:
    _arg_ (_type_): _description_

Returns:
    _type_: _description_
"""
```
