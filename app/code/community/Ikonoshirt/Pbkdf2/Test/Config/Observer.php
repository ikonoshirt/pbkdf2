<?php

class Ikonoshirt_Pbkdf2_Test_Config_Observer
    extends EcomDev_PHPUnit_Test_Case_Config
{
    /**
     *
     * @test
     */
    public function checkCustomerPasswordObserver()
    {
        $this->assertEventObserverDefined(
            'global',
            'customer_customer_authenticated',
            'ikonoshirt_pbkdf2/observer',
            'customerCustomerAuthenticated',
            'replace_md5_customer_passwords',
            'Observer to replace customer md5/sha512 passwords is not ' .
            'defined or actived'
        );
    }

    /**
     *
     * @test
     */
    public function checkAdminPasswordObserver()
    {
        $this->assertEventObserverDefined(
            'global',
            'admin_user_authenticate_after',
            'ikonoshirt_pbkdf2/observer',
            'adminUserAuthenticateAfter',
            'replace_md5_admin_passwords',
            'Observer to replace admin md5/sha512 passwords is not ' .
            'defined or actived'
        );
    }

    /**
     *
     * @test
     */
    public function checkApiPasswordObserver()
    {
        $this->assertEventObserverDefined(
            'global',
            'api_user_authenticated',
            'ikonoshirt_pbkdf2/observer',
            'apiUserAuthenticated',
            'replace_md5_api_passwords',
            'Observer to replace api md5/sha512 passwords is not ' .
            'defined or actived'
        );
    }

    /**
     *
     * @test
     */
    public function changeEncrpytionModuleToEeOrCeStub()
    {
        $this->assertEventObserverDefined(
            'global',
            'core_collection_abstract_load_before',
            'ikonoshirt_pbkdf2/observer',
            'coreCollectionAbstractLoadBefore',
            'addCustomOptionWhileEditing',
            'Observer to check wether EE or CE is in use and replace the' .
            ' encryption module is not defined or activated'
        );
    }
}