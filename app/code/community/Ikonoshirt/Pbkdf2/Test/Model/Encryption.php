<?php
error_reporting(E_ALL);ini_set('display_errors', 1);
class Ikonoshirt_Pbkdf2_Test_Model_Encryption extends EcomDev_PHPUnit_Test_Case
{
    protected $_iterationReflection;
    protected $_keyLengthReflection;
    protected $_prefixReflection;
    protected $_hashAlgorithmReflection;
    /**
     * @var Ikonoshirt_Pbkdf2_Model_Encryption
     */
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

        $_encryptionStubReflection = new ReflectionProperty(
            'Ikonoshirt_Pbkdf2_Model_Encryption',
            '_encryptionStub'
        );
        $_encryptionStubReflection->setAccessible(
            ReflectionProperty::IS_PUBLIC
        );
        $_encryptionStubReflection->setValue(
            $this->_encryption,
            Mage::getModel('ikonoshirt_pbkdf2/stub_ce')
        );
        $_encryptionStubReflection->setAccessible(
            ReflectionProperty::IS_PROTECTED
        );
    }


    public function testValidateHashWithPrefix()
    {

        $expected = '215ba609f9dfa5e74bacb787304df8a844bdff2dc9ac9e9658e'.
        'b4028660e798c23ba303fa815cda2181ae7d540dadafd21bd8ddee98dc81cc1'.
        '0898122e54133aa8ee0ad53c9636a4a8fb239c6435722b8ab97d9492a6a30f4'.
        '0aec9751bc8125184999ba973aef0cbf65159d0d02094c61d8cbf189ca17a0b'.
        '60c36364ce9031d9dfe1467b950690ba6710c53f0d5bd12a37f6889377221c1'.
        '6045d59c36773c1d7cd4c2b3b9113ae12f7ee72c4d8488a09612e57ae9ac0ce'.
        'a2752983bca87bc68203d9baa753356ea87c66bd768be08872b2dc683cd8af5'.
        '888227cff164f478bf9ed73a26b2ddd3c6d83efbae8b123cf17411e241549ee'.
        '145ec11d5bb066c15c2e:prefix4mp/f#*1(ygseÖv';

        // set all config settings
        $this->_hashAlgorithmReflection->setValue($this->_encryption, 'sha512');

        $this->_iterationReflection->setValue($this->_encryption, 1000);
        $this->_keyLengthReflection->setValue($this->_encryption, 256);
        $this->_prefixReflection->setValue($this->_encryption, 'prefix');

        // then check wether validateHash returns true
        $this->assertTrue(
            $this->_encryption->validateHash(
                'password', $expected
            )
        );
    }

    public function testValidateHashWithWrongHash()
    {
        // this is not 'password' hashed.
        $expected = '215ba609f9dfa5e74bacab787304df8a844bdff2dc9ac9e9658e'.
        'b4028660e798c23ba303fa815cda2181aae7d540dadafd21bd8ddee98dc81cc1'.
        '0898122e54133aa8ee0ad53c9636a4a8afb239c6435722b8ab97d9492a6a30f4'.
        '0aec9751bc8125184999ba973aef0cbfa65159d0d02094c61d8cbf189ca17a0b'.
        '60c36364ce9031d9dfe1467b950690baa6710c53f0d5bd12a37f6889377221c1'.
        '6045d59c36773c1d7cd4c2b3b9113ae1a2f7ee72c4d8488a09612e57ae9ac0ce'.
        'a2752983bca87bc68203d9baa753356eaa87c66bd768be08872b2dc683cd8af5'.
        '888227cff164f478bf9ed73a26b2ddd3ac6d83efbae8b123cf17411e241549ee'.
        '145ec11d5bb066c1a5c2e:prefix4mp/f#*1(ygseÖv';

        // set all config settings
        $this->_hashAlgorithmReflection->setValue($this->_encryption, 'sha512');

        $this->_iterationReflection->setValue($this->_encryption, 1000);
        $this->_keyLengthReflection->setValue($this->_encryption, 256);
        $this->_prefixReflection->setValue($this->_encryption, 'prefix');

        // then check wether validateHash returns true
        $this->assertFalse(
            $this->_encryption->validateHash(
                'password', $expected
            )
        );
    }

    public function testValidateHashWithMd5()
    {
        $expected = '5f4dcc3b5aa765d61d8327deb882cf99';
        $this->assertTrue(
            $this->_encryption->validateHash(
                'password', $expected
            )
        );
    }

    public function testValidateHashWithMd5AndSalt()
    {
        $expected = '67a1e09bb1f83f5007dc119c14d663aa:salt';
        $this->assertTrue(
            $this->_encryption->validateHash(
                'password', $expected
            )
        );
    }
}