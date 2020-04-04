<?php

class Ikonoshirt_Pbkdf2_Model_Api_User extends Mage_Api_Model_User
{
    protected function _getEncodedApiKey($apiKey)
    {
        return $this->_getHelper('core')->getHash($apiKey, Mage_Admin_Model_User::HASH_SALT_LENGTH);
    }
}
