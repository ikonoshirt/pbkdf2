<?php
class Ikonoshirt_Pbkdf2_Test_Controller_AccountController extends EcomDev_PHPUnit_Test_Case_Controller
{
    /*
     * Test data
     */
    const OLD_PASSWORD = 'oldpass',
          NEW_PASSWORD = 'newpass',
          STORE_ID     = 1,
          FIRST_NAME   = 'X',
          LAST_NAME    = 'X',
          EMAIL        = 'mail@example.com';

    /**
     * User should be able to change password from account settings
     *
     * @test
     * @registry isSecureArea
     * @singleton customer/session
     */
    public function testChangePasssword()
    {
        //Allow deleting customer model without adminhtml context
        Mage::register('isSecureArea', true);

        /* @var $store Mage_Core_Model_Store */
        $store = Mage::getModel('core/store')->load(self::STORE_ID);

        // delete account if existing
        $customer = Mage::getModel('customer/customer');
        $customer->setStore($store)->loadByEmail(self::EMAIL);
        if (!$customer->isObjectNew()) {
            $customer->delete();
        }

        $customer = Mage::getModel('customer/customer');
        /* @var $customer Mage_Customer_Model_Customer */
        $customer->setPassword(self::OLD_PASSWORD);
        $customer->setEmail(self::EMAIL);
        $customer->setStore($store);
        $customerId = $customer->save()->getId();
        $oldPasswordHash = $customer->getPasswordHash();

        $this->customerSession($customerId);
        $this->getRequest()->setMethod('POST')
            ->setPost(array(
                'firstname'        => self::FIRST_NAME,
                'lastname'         => self::LAST_NAME,
                'change_password'  => '1',
                'current_password' => self::OLD_PASSWORD,
                'password'         => self::NEW_PASSWORD,
                'confirmation'     => self::NEW_PASSWORD
            ));
        $this->dispatch('customer/account/editPost');
        /* @var Mage_Core_Model_Message_Collection $messages */
        $messages = Mage::getSingleton('customer/session')->getMessages();
        $this->assertEquals('success: The account information has been saved.', $messages->toString());
        $this->assertRedirectTo('customer/account');

        // and the password must be changed
        $customerReloaded = Mage::getModel('customer/customer')
            ->load($customerId);

        $this->assertNotEquals(
            $oldPasswordHash,
            $customerReloaded->getPasswordHash()
        );

        $customer->delete();

    }
}