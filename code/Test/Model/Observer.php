<?php

class Ikonoshirt_Pbkdf2_Test_Model_Observer extends EcomDev_PHPUnit_Test_Case
{

    /**
     * @test
     */
    public function testAdminPasswordReplaced()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * @test
     */
    public function testApiPasswordReplaced()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }

    /**
     * Check wether the hash is replaced if it is generated the old way
     *
     * @test
     */
    public function testCustomerPasswordReplaced()
    {
        // test wether the customer exists if yes delete him
        $customer = Mage::getModel('customer/customer');
        // TODO remove static 1 for website id!
        $customer->setWebsiteId(1);
        $customer->loadByEmail('mail@example.invalid');
        if (!$customer->isObjectNew()) {
            $customer->delete();
        }
        // TODO remove static 1 for store id
        $store = Mage::getModel('core/store')->load(1);
        /* @var $store Mage_Core_Model_Store */
        // create customer with old hash
        $enc = Mage::getModel('core/encryption');
        $enc->setHelper(Mage::helper('core'));
        /* @var $enc Mage_Core_Model_Encryption */
        $hash = $enc->getHash('password', 2);

        $customer = Mage::getModel('customer/customer');
        /* @var $customer Mage_Customer_Model_Customer */
        $customer->setPasswordHash($hash);
        $customer->setFirstname('Test');
        $customer->setLastname('User');
        $customer->setEmail('mail@example.invalid');
        $customer->setStore($store);
        // save the user and explicit the old hash
        $customerId = $customer->save()->getId();

        // login the user
        $customer->authenticate('mail@example.invalid', 'password');

        // after login the event must be fired
        $this->assertEventDispatchedExactly(
            'customer_customer_authenticated', 1
        );

        // and the password must be changed
        $customerReloaded = Mage::getModel('customer/customer')
            ->load($customerId);

        $this->assertNotEquals(
            $customerReloaded->getPasswordHash(),
            $hash
        );

    }

    /**
     * @test
     */
    public function testConfigurationNodeForEeReplaced()
    {
        $storeCollection = Mage::getResourceModel('core/store_collection');
        $storeCollection->load();
        $this->assertEventDispatchedExactly(
            'core_collection_abstract_load_before', 1
        );
    }
}