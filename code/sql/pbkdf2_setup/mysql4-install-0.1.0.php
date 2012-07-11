<?php
/* @var $installer Ikonoshirt_Pbkdf2_Model_Mysql4_Setup */
$installer = $this;

$installer->startSetup();

$installer->getConnection()->modifyColumn($installer->getTable('admin/user'),
    'password', 'VARCHAR(800) default NULL');

$select = $installer->getConnection()->select();
$select->from($installer->getTable('eav/entity_type'), 'entity_type_id')->where('entity_type_code = ?', 'customer');
$id = $installer->getConnection()->fetchOne($select);

$installer->getConnection()->update($installer->getTable('eav/attribute'), array('backend_type' => 'text'), "attribute_code = 'password_hash' AND entity_type_id = $id");

// TODO copy all passwords to the eav_entity_text table and encrypt the hashes with PBKDF2


$installer->endSetup();