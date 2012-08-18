<?php
error_reporting(E_ALL);ini_set('display_errors', 1);
class Ikonoshirt_Pbkdf2_Test_Model_Encryption extends EcomDev_PHPUnit_Test_Case
{

    public function testPbkdf2TestVectors()
    {

        $encryption = Mage::getModel(
            'ikonoshirt_pbkdf2/encryption',
            array(Mage::getModel('core/encryption'))
        );
        /* @var $encryption Ikonoshirt_Pbkdf2_Model_Encryption */

        // prepare all the protected properties to be changeable

        $iterationReflection =
        new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_iterations'
        );
        $iterationReflection->setAccessible(ReflectionProperty::IS_PUBLIC);

        $keyLengthReflection =         new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_keyLength'
        );
        $keyLengthReflection->setAccessible(ReflectionProperty::IS_PUBLIC);

        $prefixReflection =         new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_prefix'
        );
        $prefixReflection->setAccessible(ReflectionProperty::IS_PUBLIC);

        $hashAlgorithmReflection =         new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_hashAlgorithm'
        );
        $hashAlgorithmReflection->setAccessible(ReflectionProperty::IS_PUBLIC);


        /*
        * Input:
        *        P = "password" (8 octets)
        *        S = "salt" (4 octets)
        *        c = 1
        *        dkLen = 20
        *
        *      Output:
        *        DK = 0c 60 c8 0f 96 1f 0e 71
        *             f3 a9 b5 24 af 60 12 06
        *             2f e0 37 a6             (20 octets)
        */
        $expected = '0c60c80f961f0e71f3a9b524af6012062fe037a6:salt';

        $iterationReflection->setValue($encryption, 1);
        $keyLengthReflection->setValue($encryption, 20);
        $prefixReflection->setValue($encryption, '');
        $hashAlgorithmReflection->setValue($encryption, 'sha1');

        $this->assertEquals(
            $encryption->getHash('password', 'salt'),
            $expected
        );


        /*
         *  Input:
         *        P = "password" (8 octets)
         *        S = "salt" (4 octets)
         *        c = 2
         *        dkLen = 20
         *
         *     Output:
         *        DK = ea 6c 01 4d c7 2d 6f 8c
         *             cd 1e d9 2a ce 1d 41 f0
         *             d8 de 89 57
         */

        $expected = 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957:salt';

        $iterationReflection->setValue($encryption, 2);

        $this->assertEquals(
            $encryption->getHash('password', 'salt'),
            $expected
        );

        /*
         * Input:
         *        P = "password" (8 octets)
         *        S = "salt" (4 octets)
         *        c = 4096
         *        dkLen = 20
         *
         *      Output:
         *        DK = 4b 00 79 01 b7 65 48 9a
         *             be ad 49 d9 26 f7 21 d0
         *             65 a4 29 c1             (20 octets)
         */

        $expected = '4b007901b765489abead49d926f721d065a429c1:salt';

        $iterationReflection->setValue($encryption, 4096);

        $this->assertEquals(
            $encryption->getHash('password', 'salt'),
            $expected
        );

        /*
         * Input:
         *         P = "password" (8 octets)
         *         S = "salt" (4 octets)
         *         c = 16777216
         *         dkLen = 20
         *
         *         Output:
         *         DK = ee fe 3d 61 cd 4d a4 e4
         *         e9 94 5b 3d 6b a2 15 8c
         *         26 34 e9 84             (20 octets)
         */
        /**
         * This tests is true on my MBP, but runs 1:16min, because of the
         * iterations

        $expected = 'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984:salt';

        $iterationReflection->setValue($encryption, 16777216);

        $this->assertEquals(
            $encryption->getHash('password', 'salt'),
            $expected
        );

        */
        /*
         * Input:
         *        P = "passwordPASSWORDpassword" (24 octets)
         *        S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
         *        c = 4096
         *        dkLen = 25
         *
         *      Output:
         *        DK = 3d 2e ec 4f e4 1c 84 9b
         *             80 c8 d8 36 62 c0 e4 4a
         *             8b 29 1a 96 4c f2 f0 70
         *             38                      (25 octets)
         */

        $expected = '3d2eec4fe41c849b80c8d83662c0e44a8b291'.
        'a964cf2f07038:saltSALTsaltSALTsaltSALTsaltSALTsalt';

        $iterationReflection->setValue($encryption, 4096);
        $keyLengthReflection->setValue($encryption, 25);
        $this->assertEquals(
            $encryption->getHash(
                'passwordPASSWORDpassword',
                'saltSALTsaltSALTsaltSALTsaltSALTsalt'
            ),
            $expected
        );

        /*
         *  Input:
         *        P = "pass\0word" (9 octets)
         *        S = "sa\0lt" (5 octets)
         *        c = 4096
         *        dkLen = 16
         *
         *      Output:
         *        DK = 56 fa 6a a7 55 48 09 9d
         *             cc 37 d7 f0 34 25 e0 c3 (16 octets)
         */
        $expected = "56fa6aa75548099dcc37d7f03425e0c3:sa\0lt";

        $iterationReflection->setValue($encryption, 4096);
        $keyLengthReflection->setValue($encryption, 16);

        $this->assertEquals(
            $encryption->getHash(
                "pass\0word",
                "sa\0lt"
            ),
            $expected
        );
    }
}