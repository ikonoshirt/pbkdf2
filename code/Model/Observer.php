<?php
class Ikonoshirt_Pbkdf2_Model_Observer
{
    /**
     * If the customer's password is an old MD5 hash, and the shop-owner wants them to replaced, DO IT.
     *
     * @param $observer
     */
    public function customer_customer_authenticated($observer) {
        if(!(boolean)Mage::getStoreConfig('ikonoshirt/pbkdf2/check_legacy_hash')) {
            return;
        }

        // check wether the password is an old one
        $password = $observer->getPassword();
        /* @var $customer Mage_Customer_Model_Customer */
        $customer = $observer->getModel();

        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        /* @var $encrypter Ikonoshirt_Pbkdf2_Model_Stub_Interface */
        $encrypter = $helper->getEncryptor();

        // if the hash validates against the old hashing method, replace the hash
        if($encrypter->validateLegacyHash($password, $customer->getPasswordHash())) {
            $customer->setPassword($password);
            $customer->save();
        }
    }

    public function api_user_authenticated($observer) {
        // TODO implement and test ... only a few ideas, but I don't know the API and the apiKey storage enough
        // looks like the keys is maybe not hashed?!
        if(!(boolean)Mage::getStoreConfig('ikonoshirt/pbkdf2/check_legacy_hash')) {
            return;
        }

        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        /* @var $user Mage_Admin_Model_User */
        $user = $observer->getModel();
        $password = $observer->getApiKey();
        if($encrypter->validateLegacyHash($password, $user->getPassword())) {
            $user->setPassword($observer->getPassword());
        }
    }

    /**
     * If the admin's password is an old MD5 hash, and the shop-owner wants them to replaced, DO IT.
     *
     * @param $observer
     */
    public function admin_user_authenticate_after($observer) {
        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        /* @var $user Mage_Admin_Model_User */
        $user = $observer->getUser();
        $password = $observer->getPassword();
        if($encrypter->validateLegacyHash($password, $user->getPassword())) {
            $user->setPassword($observer->getPassword());
        }
    }

    /**
     * If the magento version is Enterprise Edition we have to change the Stub we extend from
     */
    public function controller_action_predispatch() {
        if ((string)Mage::getConfig()->getNode('modules/Enterprise_Pci/active')) {
            Mage::getConfig()->setNode('global/helpers/core/encryption_model', 'Ikonoshirt_Pbkdf2_Model_Stub_EE');

        }
    }

}
