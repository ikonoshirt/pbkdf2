<?php
/**
 * In this file you find all the observer methods used in the pbkdf2 module
 * PHP Version 5.2.13
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @version  GIT: <git_id>
 * @link     https://github.com/ikonoshirt/pbkdf2
 * @php
 */

/**
 * Observer for PBKDF2 Module
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @link     https://github.com/ikonoshirt/pbkdf2
 */
class Ikonoshirt_Pbkdf2_Model_Observer
{
    /**
     * If the customer's password is an old MD5 hash, and the shop-owner
     * wants them to replaced, DO IT.
     *
     * @param Mage_Core_Model_Observer $observer Observer with
     *                                            customer informations
     *
     * @return void
     */
    public function customerCustomerAuthenticated($observer)
    {
        if (!(boolean)Mage::getStoreConfig(
            'ikonoshirt/pbkdf2/check_legacy_hash'
        )) {
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

        // if the hash validates against the old hashing method,
        //   replace the hash
        if ($encrypter->validateLegacyHash(
            $password, $customer->getPasswordHash()
        )
        ) {
            $customer->setPassword($password);
            $customer->save();
        }
    }

    /**
     * If the api password is hashed the old way, we replace it
     *
     * @param Mage_Core_Model_Observer $observer Observer with API
     *              user informations
     *
     * @return void
     */
    public function apiUserAuthenticated($observer)
    {
        if (!(boolean)Mage::getStoreConfig(
            'ikonoshirt/pbkdf2/check_legacy_hash'
        )) {
            return;
        }

        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        /* @var $user Mage_Api_Model_User */
        $user = $observer->getModel();
        $password = $observer->getApiKey();
        Mage::log('test');
        if ($encrypter->validateLegacyHash($password, $user->getApiKey())) {
            $user->setApiKey($observer->getApiKey());
            $user->save();
        }
    }

    /**
     * If the admin's password is an old MD5 hash, and the shop-owner wants
     * them to replaced, DO IT.
     *
     * @param Mage_Core_Model_Observer $observer observer with information about
     *                                           admin user
     *
     * @return void
     */
    public function adminUserAuthenticateAfter($observer)
    {

        /* @var $helper Mage_Core_Helper_Data */
        $helper = Mage::helper('core');
        $encrypter = $helper->getEncryptor();

        /* @var $user Mage_Admin_Model_User */
        $user = $observer->getUser();
        $password = $observer->getPassword();
        if ($encrypter->validateLegacyHash($password, $user->getPassword())) {
            $user->setPassword($observer->getPassword());
            $user->save();
        }
    }

    /**
     * If the magento version is Enterprise Edition we have to change the Stub
     * we extend from
     *
     * @param Mage_Core_Model_Observer $observer Observer with event information
     *
     * @return void
     */
    public function coreCollectionAbstractLoadBefore($observer)
    {
        $isStoreCollection = $observer->getCollection() instanceof
        Mage_Core_Model_Resource_Store_Collection;
        if (!$isStoreCollection) {
            // we only want to hook up the first call of this event.
            // The first call is for the store collection
            return;
        }
        // Mage_Core_Model_Resource_Store_Collection

        // only replace if the version is EE and has a
        // Enterprice_Pci module installed
        if ((string)Mage::getConfig()->getNode(
            'modules/Enterprise_Pci/active'
        )) {
            Mage::getConfig()->setNode(
                'global/helpers/core/encryption_model',
                'Ikonoshirt_Pbkdf2_Model_Stub_EE'
            );

        }
    }

}
