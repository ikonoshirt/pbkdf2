<?php
interface Ikonoshirt_Pbkdf2_Model_Stub_Interface {
    public function validateHash($password, $hash);
    public function getHash($password, $salt = false);
    public function getHelper();
    public function validateLegacyHash($password, $hash);
}