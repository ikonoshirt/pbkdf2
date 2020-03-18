# Ikonoshirt_Pbkdf2

Ikonoshirt_Pbkdf2 implements PBKDF2 (http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf) for the basic password hashing in Magento. You have the choice between many hash-algos, iteration-count, key-length, etc. Have a look into the config.xml

This module changes by default all passwords of the user AFTER THEIR login to the recommended method for password "hashing" PBKDF2! All password means: Customer, Admin and passwords for the API.

It is important to understand, that the password is replaced AFTER login. It means, after you installed the module, the old, weak password hashes are still in the database!

This module should be compatible to Magento EE - the tests run on mage-lite (certification version)

# Installation

*CHANGE THIS!*
prefix: my_magento_store

## Magento 1.9.4.4
In 1.9.4.4 the password column of admin is changed to VARCHAR 255, which is too short for this module. I hope the coreHack.sql fixes this.

## For Developers

We have overwritten no classes.

We changed the encryption model in global/helpers/core/encryption_model and use a few events to replaces the passwords after login. This is configurable, have a look at the settings.

## Fully(?) tested
I tested everything I thought it is a good idea. If you find a bug, open an issue, send a pull request, write a test, it's up to you.

For found bugs, I use TDD, so first write a test which fails and is ok after the fix.

## Thanks

Thanks to thebod for talking all the time about security and teaching a sense for it.

Thanks to vinai for the chats about implementation and the practical help AND for reading and comparing the RFC to the pbkfd2 implementation.

Thanks to  Ivan Chepurnyi and the EcomDev team for writing EcomDev_PHPUnit: https://github.com/IvanChepurnyi/EcomDev_PHPUnit

Thanks to Anthony Ferrara who built PHP-CryptLib and provides test vectors for pbkdf2 and sha512 (https://github.com/ircmaxell/PHP-CryptLib)

##Attention!
This Module changes the password creation and validation of magento.

## Parameter and Defaults
Iterations used for the PBKDF2, >= 1000 recommended
This is the main factor to slow down the hashing
iterations: 10000

Used hash algo, checked agains hash_algos()
http://de2.php.net/hash_algos
hash_algorithm: sha512

Length of the key saved in the database
Attention! This is the binary value, the hex-string is two times that length!
key_length: 256

Length of the salt used, >= 14 recommended
salt_length: 16

"Optionally, to avoid any possible interaction between other applications that use a salt, an application-, message- or user-specific variable called purpose may be prefixed to the randomly generated part of the salt as given below;
S = purpose || rv."

CHANGE THIS!
prefix: my_magento_store

If you have a running shop, all password hashes of the user were encrypted with md5.
You have to activate this option to check for the old hash too.
check_legacy_hash: 1

## TODO
- Add a admin-formular to change all passwords to new ones and send mails with new passwords
