<?php
/**
 * Internationalisation file for AccessControl extension.
 *
 * @addtogroup Extensions
 */

$messages = array();

$messages['en'] = array(
	'accesscontrol-desc' => 'Enables group access restriction on a page by user basis',
	'accesscontrol-group' => 'This page is only accessible for group $1.',
	'accesscontrol-groups' => 'This page is only accessible for the groups $1.', // FIXME: Add PLURAL and/or merge with the above message
	'accesscontrol-info' => 'This is a protected page!',
	'accesscontrol-info-user' => 'Only_sysop',
	'accesscontrol-info-anonymous' => 'No_anonymous',
	'accesscontrol-info-deny' => 'No_Access',
	'accesscontrol-edit-anonymous' => 'Deny_anonymous',
	'accesscontrol-edit-users' => 'Deny_edit_list',
);

/** Czech (Česky)
 * @author Aleš Kapica
 */
$messages['cs'] = array(
	'accesscontrol-desc' => 'Toto je rozšíření, které přidává uživatelskou možnost omezení přístupu ke stránce',
	'accesscontrol-group' => 'Tato stránka je přístupná pouze pro skupinu $1 !!!',
	'accesscontrol-groups' => 'Tato stránka je přístupná pouze pro skupiny $1 !!!',
	'accesscontrol-info' => 'Toto je stránka s omezeným přístupem!',
	'accesscontrol-info-user' => 'Stránka má omezený přístup k administraci',
	'accesscontrol-info-anonymous' => 'Ke stránce je zakázán anonymní přístup',
	'accesscontrol-info-deny' => 'Stránka má omezený přístup',
	'accesscontrol-edit-anonymous' => 'Jen pro registrované',
	'accesscontrol-edit-users' => 'Stránka jen pro správce',
);

