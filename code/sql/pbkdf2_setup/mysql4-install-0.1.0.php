<?php
/* @var $installer Ikonoshirt_Pbkdf2_Model_Mysql4_Setup */
$installer = $this;

$installer->startSetup();

$installer->getConnection()->modifyColumn(
    $installer->getTable('admin/user'), 'password', 'VARCHAR(800) default NULL'
);

$installer->updateAttribute('customer', 'password_hash', 'backend_type', 'text');

// TODO copy all passwords to the eav_entity_text table and encrypt the hashes with PBKDF2

$installer->endSetup();