<?php
/**
 * In this file you find the interface with the methods which needed
 * to be overwritten to change the magento hashing behaviour for passwords
 *
 * PHP Version 5.2.13
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @version  GIT: <git_id>
 * @link     https://github.com/ikonoshirt/pbkdf2
 * @php
 */

/**
 * Encryption interface
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @link     https://github.com/ikonoshirt/pbkdf2
 */
interface Ikonoshirt_Pbkdf2_Model_Stub_Interface
{

    /**
     * validate the password against the hash
     *
     * @param $password password
     * @param $hash     hash to validate against
     *
     * @return boolean
     */
    public function validateHash($password, $hash);

    /**
     * get the password hashed with the passed salt
     *
     * @param  string       $password the users password
     * @param bool|string   $salt if false, then a salt will be
     *                            generated, if string, the string will be used
     *
     * @return string the hashed password with the salt
     */
    public function getHash($password, $salt = false);

    /**
     * the helper of the Mage_Core_Model_Encryption
     *
     * the helper is protected and we are building a proxy, so we
     * need access to the helper class
     *
     * @return Mage_Core_Helper_Abstract
     */
    public function getHelper();

    /**
     * validate a password against an hashed password the old way
     *
     * magento ce hashes a password with md5
     * magento ee hashed the password with sha256
     *
     * @param $password the password
     * @param $hash the hash
     *
     * @return boolean
     */
    public function validateLegacyHash($password, $hash);
}