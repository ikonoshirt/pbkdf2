<?php
/* @var $installer Ikonoshirt_Pbkdf2_Model_Mysql4_Setup */
$installer = $this;

$installer->startSetup();

$installer->getConnection()->modifyColumn(
    $installer->getTable('api/user'), 'api_key', 'TEXT default NULL'
);

$installer->endSetup();