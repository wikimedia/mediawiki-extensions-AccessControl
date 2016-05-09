<?php

/* MediaWiki extension that enables group access restriction on a page-by-page
 * basis contributed by Martin Mueller (http://blog.pagansoft.de) based into
 * version 1.3 on accesscontrol.php by Josh Greenberg.
 * Version 2.0 for MediaWiki >= 1.18 rewrited completly by Aleš Kapica.
 * @package MediaWiki
 * @subpackage Extensions
 * @author Aleš Kapica
 * @copyright 2008-2014 Aleš Kapica
 * @licence GNU General Public Licence
 */

if ( !defined( 'MEDIAWIKI' ) ) {
	echo "This file is an extension to the MediaWiki software and cannot be used standalone.\n";
	die();
}

// sysop users can read all restricted pages
$wgAdminCanReadAll = true;
$wgAccessControlRedirect = true;

$wgExtensionCredits['parserhook'][] = [
	'path' => __FILE__,
	'name' => 'AccessControl',
	'author' => [ '[https://www.mediawiki.org/wiki/m:User:Want Aleš Kapica]' ],
	'url' => 'http://www.mediawiki.org/wiki/Extension:AccessControl',
	'version' => '2.6',
	'descriptionmsg' => 'accesscontrol-desc'
];

$wgAutoloadClasses['AccessControlHooks'] = __DIR__ . '/AccessControl.hooks.php';

$wgHooks['ParserFirstCallInit'][] = 'AccessControlHooks::accessControlExtension';

$wgMessagesDirs['AccessControl'] = __DIR__ . '/i18n';

// Hook the userCan function for bypassing the cache
$wgHooks['userCan'][] = 'AccessControlHooks::onUserCan';

// Hook the UnknownAction function for information user about restrictions
$wgHooks['UnknownAction'][] = 'AccessControlHooks::onUnknownAction';
