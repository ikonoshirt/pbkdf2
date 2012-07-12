<?php

$file = '/shell/abstract.php';
for ($path = '/../../', $i = 0; ! file_exists(dirname(__FILE__) . $path . $file) && $i++ < 10; $path .= '../');
require_once dirname(__FILE__) . $path . $file;

class Ikonoshirt_Pbkdf2_Shell_SetAdminPass extends Mage_Shell_Abstract
{
    public function run()
    {
        Mage::setIsDeveloperMode(true);
        $login = $this->getArg('user');
        $pass  = $this->getArg('pass');

        if (false === $pass) {
            $pass = $this->_askPass();
        }

        $user = $this->getUser($login);
        if (! $user->getId()) {
            fwrite(STDERR, sprintf("Unknown admin user: %s\n", $user));
            exit(2);
        }

        $user->setNewPassword($pass)->save();

        echo "Password updated\n";
    }

    protected function _askPass()
    {
        printf("Enter new password: ");
        `stty -echo`; //turn echo off
        $str = '';
        do {
            $c = fgetc(STDIN);
            if (in_array($c, array("\n", "\r", "\x04"))) {
                break;
            }
            $str .= $c;
        } while (true);
        `stty echo`; //turn back on
        return $str;
    }

    /**
     * @param string $login
     * @return Mage_Admin_Model_User
     */
    protected function getUser($login)
    {
        return Mage::getModel('admin/user')->loadByUsername($login);
    }
}

$instance = new Ikonoshirt_Pbkdf2_Shell_SetAdminPass();
$instance->run();