<?php
class Ikonoshirt_Pbkdf2_Model_Encryption extends Mage_Core_Model_Encryption
{

    protected $_iterations = 10000;
    protected $_hashAlgorithm = 'sha512';
    protected $_keyLength = 256;
    protected $_saltLength = 16;
    protected $_checkLegacy = false;


    function __construct()
    {
        $this->_iterations = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/iterations');
        $this->_hashAlgorithm = Mage::getStoreConfig('ikonoshirt/pbkdf2/hash_algorithm');
        $this->_keyLength = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/key_length');
        $this->_saltLength = (int)Mage::getStoreConfig('ikonoshirt/pbkdf2/salt_length');
        $this->_checkLegacy = (boolean)Mage::getStoreConfig('ikonoshirt/pbkdf2/check_legacy_hash');
    }


    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - a random will be generated
     * integer - a random with specified length will be generated
     * string
     *
     * @param string $password
     * @param mixed $salt
     * @return string
     */
    public function getHash($password, $salt = false)
    {
        if (false === $salt) {
            // if no salt was passed, use the old method
            return $this->hash($password);
        }

        if (is_integer($salt)) {
            if ($salt < $this->_saltLength) {
                //Mage::log('Changed salt length from ' . $salt . ' to ' . $this->_saltLength . '.');
                $salt = $this->_saltLength;
            }
            $salt = $this->_helper->getRandomString($salt);
        }

        return $this->_pbkdf2($this->_hashAlgorithm, $password, $salt, $this->_iterations, $this->_keyLength) . ':' . $salt;
    }

    /**
     * Validate hash against hashing method (with or without salt)
     *
     * @param string $password
     * @param string $hash
     * @return bool
     * @throws Exception
     */
    public function validateHash($password, $hash)
    {
        $hashArr = explode(':', $hash);
        switch (count($hashArr)) {
            case 1:
                // Should support for non-Magento, simple hash passwords be phased out with this module?
                return $this->hash($password) === $hash;
            case 2:
                $result = $this->_pbkdf2($this->_hashAlgorithm, $password, $hashArr[1], $this->_iterations, $this->_keyLength) === $hashArr[0];
                if (!$result && $this->_checkLegacy) {
                    if ($result = parent::validateHash($password, $hash)) {
                        // Update the customers password hash to pbkdf2
                        // Further processing is done in the observer
                        Mage::getSingleton('customer/session')->setUpdatePasswdHashFlag(true);
                    }
                }
                return $result;
        }
        Mage::throwException('PBKDF2 ERROR: Invalid hash');
    }

    /*
    * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
    * $algorithm - The hash algorithm to use. Recommended: SHA256
    * $password - The password.
    * $salt - A salt that is unique to the password.
    * $count - Iteration count. Higher is better, but slower. Recommended: At least 1024.
    * $key_length - The length of the derived key in bytes.
    * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
    * Returns: A $key_length-byte key derived from the password and salt.
    *
    * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
    *
    * This implementation of PBKDF2 was originally created by defuse.ca
    * With improvements by variations-of-shadow.com
    */
    protected function _pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower($algorithm);
        if (!in_array($algorithm, hash_algos(), true))
            Mage::throwException('PBKDF2 ERROR: Invalid hash algorithm ' . $algorithm);
        if ($count <= 0 || $key_length <= 0)
            Mage::throwException('PBKDF2 ERROR: Invalid parameters.');

        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($key_length / $hash_length);

        // See Section 5.2 of the RFC 2898
        if ($key_length > (pow(2, 32) - 1) * $hash_length) {
            Mage::throwException('PBKDF2 ERROR: Invalid parameter: derived key too long.');
        }

        $output = "";
        for ($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if ($raw_output)
            return substr($output, 0, $key_length);
        else
            return bin2hex(substr($output, 0, $key_length));
    }

}