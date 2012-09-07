<?php
/**
 * In this file you find the stub of the encryption class
 * for the magneto enterprise edition
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
 * Encryption class for magento enterprise edition
 *
 * @category Magento
 * @package  Ikonoshirt_Pbkdf2
 * @author   Fabian Blechschmidt <fabian.blechschmidt@ikonoshirt.de>
 * @license  http://www.ikonoshirt.de/stuff/licenses/beerware-fabian.txt THE BEER-WARE LICENSE
 * @link     https://github.com/ikonoshirt/pbkdf2
 */
class Ikonoshirt_Pbkdf2_Model_Stub_EE extends Enterprise_Pci_Model_Encryption
    implements Ikonoshirt_Pbkdf2_Model_Stub_Interface
{
    /**
     * Model with implemented logic
     *
     * @var Ikonoshirt_Pbkdf2_Model_Encryption
     */
    protected $_realHashModel;

    public function __construct()
    {
        $this->_realHashModel = Mage::getModel(
            'ikonoshirt_pbkdf2/encryption', array($this)
        );
    }

    public function validateHash($password, $hash)
    {
        return $this->_realHashModel->validateHash($password, $hash);
    }

    public function getHash($password, $salt = false)
    {
        return $this->_realHashModel->getHash($password, $salt);
    }

    public function getHelper()
    {
        return $this->_helper;
    }

    public function validateLegacyHash($password, $hash)
    {
        return parent::validateHash($password, $hash);

    }

}