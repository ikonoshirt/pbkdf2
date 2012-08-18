<?php

class Ikonoshirt_Pbkdf2_Test_Config_Configuration
    extends EcomDev_PHPUnit_Test_Case_Config
{
    /**
     * check standard values for the encryption config
     *
     * @test
     */
    public function checkStandardConfigurationValues()
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
}