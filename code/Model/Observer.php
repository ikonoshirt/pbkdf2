<?php

class Ikonoshirt_Pbkdf2_Model_Observer
{
    public function customerCustomerAuthenticated(Varien_Event_Observer $observer)
    {
        if (Mage::getSingleton('customer/session')->getUpdatePasswdHashFlag(true))
        {
            $observer->getModel()->changePassword($observer->getPassword());
        }
    }
}
