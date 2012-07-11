Ikonoshirt_Pbkdf2
=================
Ikonoshirt_Pbkdf2 implements PBKDF2 for the basic password hashing. You have the choice between many hash-algos, iteration-count, key-length, etc. Have a look into the config.xml

Dependencies
------------
- MySQL 5.0.3 - the password field in the admin_user and customer-table will be extended to 300chars, MySQL < 5.0.3 can only hold 255 chars in a VARCHAR field
