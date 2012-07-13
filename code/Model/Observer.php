<?php
class Ikonoshirt_Pbkdf2_Model_Observer
{
    /**
     * If the password is an old MD5 hash, and the shop-owner wants them to replaced, DO IT.
     *
     * @param $observer
     */
    public function customer_customer_authenticated($observer) {
        if(!(boolean)Mage::getStoreConfig('ikonoshirt/pbkdf2/check_legacy_hash')) {
            return;
        }
        $password = $observer->getPassword();
        /* @var $customer Mage_Customer_Model_Customer */
        $customer = $observer->getModel();

        $key_length = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/key_length');

        if(strlen($customer->getPasswordHash()) != $key_length) {
            $customer->setPassword($password);
            $customer->save();
        }
    }
}
