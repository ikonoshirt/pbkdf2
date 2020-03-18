Ikonoshirt_Pbkdf2
=================
Ikonoshirt_Pbkdf2 implements PBKDF2 for the basic password hashing. You have the choice between many hash-algos, iteration-count, key-length, etc. Have a look into the config.xml

Attention!
----------
This Module changes the password creation and validation of magento. At the moment ALL old passwords are useless. Don't use it in production! My first tests are good and the login for admin and customer works - AFTER creating new passwords.

If you use this extension, use it, BEFORE the launch of the shop. Afterwards you have to create new passwords for all users (Password forgotton-function)

# Magento 1.9.4.4
In 1.9.4.4 the password column of admin is changed to VARCHAR 255, which is too short for this module. I hope the coreHack.sql fixes this.

Dependencies
------------
- MySQL 5.0.3 - the password field in the admin_user and customer-table will be extended to 300chars, MySQL < 5.0.3 can only hold 255 chars in a VARCHAR field
