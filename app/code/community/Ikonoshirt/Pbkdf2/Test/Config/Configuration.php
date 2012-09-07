<?php

class Ikonoshirt_Pbkdf2_Test_Config_Configuration
    extends EcomDev_PHPUnit_Test_Case_Config
{
    /**
     * check standard values for the encryption config
     *
     * @test
     */
    public function checkStandardConfigurationValuesForPbkdf2()
    {
        $this->assertConfigNodeHasChildren('default/ikonoshirt/pbkdf2');

        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/iterations', 10000
        );
        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/hash_algorithm', 'sha512'
        );
        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/key_length', 256
        );
        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/salt_length', 16
        );
        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/prefix', 'prefix'
        );
        $this->assertConfigNodeContainsValue(
            'default/ikonoshirt/pbkdf2/check_legacy_hash', 1
        );
    }

    /**
     * @test
     */
    public function checkModelConfiguration()
    {
        $this->assertModelAlias(
            'ikonoshirt_pbkdf2/encryption',
            'Ikonoshirt_Pbkdf2_Model_Encryption'
        );
    }

    public function checkEncryptionClassOverwrite()
    {
        $this->assertConfigNodeContainsValue(
            'global/helpers/core/encryption_model',
            'Ikonoshirt_Pbkdf2_Model_Stub_CE'
        );
    }
}