<?php

declare(strict_types=1);

class Ikonoshirt_Pbkdf2_Model_Api_User extends Mage_Api_Model_User
{
    protected function _getEncodedApiKey($apiKey)
    {
        return Mage::helper('core')->getHash($apiKey);
    }
}
