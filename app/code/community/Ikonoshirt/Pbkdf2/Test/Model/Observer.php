<?php

class Ikonoshirt_Pbkdf2_Test_Model_Observer extends EcomDev_PHPUnit_Test_Case_Controller
{
    /**
     * @test
     * @singleton admin/session
     */
    public function testAdminPasswordReplaced()
    {
        //Mock session model to prevent session_start()
        $this->replaceByMock('singleton', 'admin/session',
            $this->getModelMock('admin/session', array(), false, array(), '', false));
        //Reflection to set old password
        $dataReflection = new ReflectionProperty(
            'Mage_Admin_Model_User', '_data'
        );
        $dataReflection->setAccessible(ReflectionProperty::IS_PUBLIC);

        // we need to set the orig data too to prevend the hashing of
        // the "new" password
        $origDataReflection = new ReflectionProperty(
            'Mage_Admin_Model_User', '_origData'
        );
        $origDataReflection->setAccessible(ReflectionProperty::IS_PUBLIC);


        // delete account if existing
        $adminUser = Mage::getModel('admin/user');
        $adminUser->loadByUsername('passwordReplacementTest');
        if (!$adminUser->isObjectNew()) {
            $adminUser->delete();
        }

        /* @var $store Mage_Core_Model_Store */
        // create customer with old hash
        $enc = Mage::getModel('core/encryption');
        $helper = Mage::helper('core');
        /* @var $helper Mage_Core_Helper_Data */
        $enc->setHelper($helper);
        /* @var $enc Mage_Core_Model_Encryption */
        // "old way" to hash password
        $hash = $enc->getHash('password', 2);

        $adminUser = Mage::getModel('admin/user');
        /* @var $adminUser Mage_Admin_Model_User */
        $adminUser->setUsername('passwordReplacementTest');
        $adminUser->setIsActive(1);
        // set password hash in data Array
        $passwordArray = array('password' => $hash);
        $dataReflection->setValue(
            $adminUser,
            array_merge($dataReflection->getValue($adminUser), $passwordArray)
        );

        // set origData password
        $origDataReflection->setValue(
            $adminUser,
            $passwordArray
        );

        // save the user and explicit the old hash
        $adminUserId = $adminUser->save()->getId();

        // add to group administrators
        $adminUser->setRoleIds(array(1))
        ->setRoleUserId($adminUser->getUserId())
        ->saveRelations();

        // login the user
        $adminUser->authenticate('passwordReplacementTest', 'password');

        // after login the event must be fired
        $this->assertEventDispatchedExactly(
            'admin_user_authenticate_after', 1
        );

        // and the password must be changed
        /* @var $adminReloaded Mage_Admin_Model_User */
        $adminReloaded = Mage::getModel('admin/user')
        ->load($adminUserId);

        // the hash needs to be changed after the login
        $this->assertNotEquals(
            $adminReloaded->getPassword(),
            $hash
        );

        // clean up the user
        $adminUser->delete();
    }

    /**
     * @test
     */
    public function testApiPasswordReplaced()
    {

        //Reflection to set old password
        $dataReflection = new ReflectionProperty(
            'Mage_Api_Model_User', '_data'
        );
        $dataReflection->setAccessible(ReflectionProperty::IS_PUBLIC);

        // we need to set the orig data too to prevend the hashing of
        // the "new" password
        $origDataReflection = new ReflectionProperty(
            'Mage_Api_Model_User', '_origData'
        );
        $origDataReflection->setAccessible(ReflectionProperty::IS_PUBLIC);


        // delete account if existing
        $apiUser = Mage::getModel('api/user');
        $apiUser->loadByUsername('passwordReplacementTest');
        if (!$apiUser->isObjectNew()) {
            $apiUser->delete();
        }


        // create new role
        $role = Mage::getModel('api/roles')
        ->setName('admin')
        ->setPid(false)
        ->setRoleType('G')
        ->save();

        Mage::getModel("api/rules")
        ->setRoleId($role->getId())
        ->setResources(array('all'))
        ->saveRel();

        $apiUser = Mage::getModel('api/user');
        $apiUser->setData(
            array(
                'username' => 'passwordReplacementTest',
                'firstname' => 'admin',
                'lastname' => 'admin',
                'email' => 'mail@example.invalid',
                'is_active' => 1,
                'user_roles' => '',
                'assigned_user_role' => '',
                'role_name' => '',
                'roles' => array($role->getId())
            )
        );

        /* @var $store Mage_Core_Model_Store */
        // create customer with old hash
        $enc = Mage::getModel('core/encryption');
        $helper = Mage::helper('core');
        /* @var $helper Mage_Core_Helper_Data */
        $enc->setHelper($helper);
        /* @var $enc Mage_Core_Model_Encryption */
        // "old way" to hash password
        $hash = $enc->getHash('password', 2);

        $apiUser = Mage::getModel('api/user');
        /* @var $apiUser Mage_Api_Model_User */
        $apiUser->setUsername('passwordReplacementTest');
        $apiUser->setIsActive(1);
        // set password hash in data Array
        $apiKeyArray = array('api_key' => $hash);
        $dataReflection->setValue(
            $apiUser,
            array_merge($dataReflection->getValue($apiUser), $apiKeyArray)
        );

        // set origData password
        $origDataReflection->setValue(
            $apiUser,
            $apiKeyArray
        );

        // save the user and explicit the old hash
        $apiUser->getResource()->save($apiUser);
        $apiUserId = $apiUser->getId();

        $apiUser->setRoleIds(array($role->getId()))
        ->setRoleUserId($apiUser->getUserId())
        ->saveRelations();

        // login the user
        $apiUser->login('passwordReplacementTest', 'password');

        // after login the event must be fired
        $this->assertEventDispatchedExactly(
            'api_user_authenticated', 1
        );

        // and the password must be changed
        /* @var $apiUserReloaded Mage_Api_Model_User */
        $apiUserReloaded = Mage::getModel('api/user')
        ->load($apiUserId);

        // the hash needs to be changed after the login
        $this->assertNotEquals(
            $apiUserReloaded->getApiKey(),
            $hash
        );

        // clean up the user
        $apiUser->delete();
    }

    /**
     *
     * @test
     * @registry isSecureArea
     */
    public function testCustomerPasswordReplaced()
    {
        //Allow deleting customer model without adminhtml context
        Mage::register('isSecureArea', true);
        // TODO remove static 1 for store id
        $store = Mage::getModel('core/store')->load(1);
        /* @var $store Mage_Core_Model_Store */
        // create customer with old hash
        $enc = Mage::getModel('core/encryption');
        $enc->setHelper(Mage::helper('core'));
        /* @var $enc Mage_Core_Model_Encryption */
        $hash = $enc->getHash('password', 2);

        // delete account if existing
        $customer = Mage::getModel('customer/customer');
        $customer->setStore($store)->loadByEmail('mail@example.invalid');
        if (!$customer->isObjectNew()) {
            $customer->delete();
        }

        $customer = Mage::getModel('customer/customer');
        /* @var $customer Mage_Customer_Model_Customer */
        $customer->setPasswordHash($hash);
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

        $customer->delete();

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