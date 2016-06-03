<?php

/**
 * MediaWiki extension that enables group access restriction on a page-by-page
 * basis
 *
 * Version pre-0.1 (2005-05-03) by Josh Greenberg
 * Version 0.1 to 0.9 (2010-06-27) by Martin Gondermann
 * Version 1.0 to 2.5 by Aleš Kapica
 * Version 2.6 by Siebrand Mazeland and Thomas Mulhall
 *
 * @package MediaWiki
 * @subpackage Extensions
 * @author Aleš Kapica
 * @copyright 2008-2014 Aleš Kapica
 * @license GNU General Public Licence 2.0 or later
 */

// Ensure that the script cannot be executed outside of MediaWiki
if ( !defined( 'MEDIAWIKI' ) ) {
	echo "This file is an extension to the MediaWiki software and cannot be used standalone.\n";
	die();
}

// Register extension with MediaWiki
$wgExtensionCredits['parserhook'][] = [
	'path' => __FILE__,
	'name' => 'AccessControl',
	'author' => [
		'[https://www.mediawiki.org/wiki/m:User:Want Aleš Kapica]'
	],
	'url' => 'https://www.mediawiki.org/wiki/Extension:AccessControl',
	'version' => '2.6',
	'descriptionmsg' => 'accesscontrol-desc',
	'license-name' => 'GPL-2.0+'
];

// Set extension specific parameters
// sysop users can read all restricted pages
$wgAdminCanReadAll = true;
// do not redirect from page in search results to restricted pages
$wgAccessControlRedirect = true;

// Load extension's class
$wgAutoloadClasses['AccessControlHooks'] = __DIR__ . '/AccessControl.hooks.php';

// Register extension's messages
$wgMessagesDirs['AccessControl'] = __DIR__ . '/i18n';

// Register hooks
// Hook the ParserFirstCallInit for
$wgHooks['ParserFirstCallInit'][] = 'AccessControlHooks::accessControlExtension';
// Hook the userCan function for bypassing the cache
$wgHooks['userCan'][] = 'AccessControlHooks::onUserCan';
// Hook the UnknownAction function for information user about restrictions
$wgHooks['UnknownAction'][] = 'AccessControlHooks::onUnknownAction';
