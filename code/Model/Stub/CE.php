<?php
class Ikonoshirt_Pbkdf2_Model_Stub_CE extends Mage_Core_Model_Encryption implements Ikonoshirt_Pbkdf2_Model_Stub_Interface
{
    /**
     * Model with implemented logic
     *
     * @var Ikonoshirt_Pbkdf2_Model_Encryption
     */
    protected $_realHashModel;

    public function __construct()
    {
        $this->_realHashModel = Mage::getModel('ikonoshirt_pbkdf2/encryption', array($this));
    }

    public function validateHash($password, $hash)
    {
        return $this->_realHashModel->validateHash($password, $hash);
    }

    public function getHash($password, $salt = false)
    {
        return $this->_realHashModel->getHash($password, $salt);
    }

    public function getHelper()
    {
        return $this->_helper;
    }

    public function validateLegacyHash($password, $hash)
    {
        return parent::validateHash($password, $hash);

    }

}