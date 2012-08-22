<?php

class Ikonoshirt_Pbkdf2_Test_Model_EncryptionHashing extends EcomDev_PHPUnit_Test_Case
{
    protected $_iterationReflection;
    protected $_keyLengthReflection;
    protected $_prefixReflection;
    protected $_hashAlgorithmReflection;
    protected $_encryption;

    public function tearDown()
    {
        $this->_encryption = null;
        $this->_hashAlgorithmReflection = null;
        $this->_iterationReflection = null;
        $this->_keyLengthReflection = null;
        $this->_prefixReflection = null;
    }

    public function setUp()
    {
        $this->_encryption = Mage::getModel(
            'ikonoshirt_pbkdf2/encryption',
            array(Mage::getModel('core/encryption'))
        );
        /* @var $this->_encryption Ikonoshirt_Pbkdf2_Model_Encryption */

        // prepare all the protected properties to be changeable

        $this->_iterationReflection =
        new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_iterations'
        );
        $this->_iterationReflection->setAccessible(
            ReflectionProperty::IS_PUBLIC
        );

        $this->_keyLengthReflection = new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_keyLength'
        );
        $this->_keyLengthReflection->setAccessible(
            ReflectionProperty::IS_PUBLIC
        );

        $this->_prefixReflection = new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_prefix'
        );
        $this->_prefixReflection->setAccessible(
            ReflectionProperty::IS_PUBLIC
        );

        $this->_hashAlgorithmReflection = new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_hashAlgorithm'
        );
        $this->_hashAlgorithmReflection->setAccessible(
            ReflectionProperty::IS_PUBLIC
        );
    }

    /**
     * all the sha1 test vectors from here https://www.ietf.org/rfc/rfc6070.txt
     *
     * @return array
     */
    public function providePbkdf2Sha1TestVectors()
    {
        return array(
            array(
                '0c60c80f961f0e71f3a9b524af6012062fe037a6', //expected
                1, // iterations
                20, // keyLength
                'password', // password
                'salt' // salt
            ),
            array(
                'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
                2,
                20,
                'password',
                'salt'
            ),
            array(
                '4b007901b765489abead49d926f721d065a429c1',
                4096,
                20,
                'password',
                'salt'
            ),
            /* hashing 16777216 really needs time :-) */
//            array(
//                'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984',
//                16777216,
//                20,
//                'password',
//                'salt'
//            ),
            array(
                '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
                4096,
                25,
                'passwordPASSWORDpassword',
                'saltSALTsaltSALTsaltSALTsaltSALTsalt'
            ),
            array(
                '56fa6aa75548099dcc37d7f03425e0c3',
                4096,
                16,
                "pass\0word",
                "sa\0lt"
            )
        );


    }

    /**
     * @dataProvider providePbkdf2Sha1TestVectors
     */
    public function testPbkdf2Sha1TestVectors($expected, $iterations,
                                              $keyLength, $password, $salt)
    {
        $this->_hashAlgorithmReflection->setValue($this->_encryption, 'sha1');


        $this->_iterationReflection->setValue($this->_encryption, $iterations);
        $this->_keyLengthReflection->setValue($this->_encryption, $keyLength);
        $this->_prefixReflection->setValue($this->_encryption, '');


        $this->assertEquals(
            $this->_encryption->getHash($password, $salt),
            $expected . ':' . $salt
        );
    }

    /**
     * @test
     * @dataProvider providePbkdf2Sha512TestVectors
     * @throws RuntimeException
     */
    public function testPbkdf2Sha512TestVectors($password, $algo,
                                                $iterations, $keyLength,
                                                $salt, $hash)
    {
        // initialize prefix
        $this->_prefixReflection->setValue($this->_encryption, '');


        $this->_iterationReflection->setValue(
            $this->_encryption,
            $iterations
        );

        $this->_keyLengthReflection->setValue(
            $this->_encryption,
            $keyLength
        );
        if ($algo == 'pbkdf2-sha512') {
            $this->_hashAlgorithmReflection->setValue(
                $this->_encryption,
                'sha512'
            );
        } else {
            throw new RuntimeException(
                'Hash algorithm is not implemented in test.'
            );
        }

        $this->assertEquals(
            $this->_encryption->getHash(
                $password,
                $salt
            ),
            $hash . ':' . $salt
        );
    }

    /**
     * @static
     * @return array
     */
    public static function providePbkdf2Sha512TestVectors()
    {
        $results = array();
        $file = file(__DIR__ . '/../data/sha512.test-vectors');
        foreach ($file as $line) {
            list($password, $rest) = explode(' ', $line);

            list(, , $algo, $iterations, $keyLength, $salt, $hash) =
            explode('$', $rest);

            $results[] = array(
                $password,
                $algo,
                $iterations,
                $keyLength,
                base64_decode($salt),
                bin2hex(base64_decode($hash))
            );
        }

        return $results;
    }
}