<?php

/* MediaWiki extension that enables group access restriction on a page-by-page
 * basis contributed by Martin Mueller (http://blog.pagansoft.de) based into 
 * version 1.3 on accesscontrol.php by Josh Greenberg.
 * Version 2.0 for MediaWiki >= 1.18 rewrited completly by Aleš Kapica.
 * @package MediaWiki
 * @subpackage Extensions
 * @author Aleš Kapica
 * @copyright 2008-2012 Aleš Kapica
 * @licence GNU General Public Licence
 */

if( !defined( 'MEDIAWIKI' ) ) {
	echo ( "This file is an extension to the MediaWiki software and cannot be used standalone.\n" );
	die();
}

// sysop users can read all restricted pages
$wgAdminCanReadAll = true;

$wgExtensionCredits['specialpage']['AccessControl'] = array(
	'name'                  => 'AccessControlExtension',
	'author'                => array( 'Aleš Kapica' ),
	'url'                   => 'http://www.mediawiki.org/wiki/Extension:AccessControl',
	'version'               => '2.1',
	'description'           => 'Access control based on users lists. Administrator rights need not be for it.',
	'descriptionmsg'        => 'accesscontrol-desc',
);

$wgHooks['ParserFirstCallInit'][] = 'wfAccessControlExtension' ;

$dir = dirname( __FILE__ ) . '/';
$wgExtensionMessagesFiles['AccessControl'] = $dir . 'AccessControl.i18n.php';


//Hook the userCan function for bypassing the cache
$wgHooks['userCan'][] = 'hookUserCan';

function wfAccessControlExtension( Parser $parser ) {
	/* This the hook function adds the tag <accesscontrol> to the wiki parser */
	$parser->setHook( "accesscontrol", "doControlUserAccess" );
	return true;
}

function doControlUserAccess( $input, array $args, Parser $parser, PPFrame $frame ) {
	/* Funcion called by wfAccessControlExtension */
	return displayGroups();
}

function accessControl( $obsahtagu ){
	$accessgroup = Array( Array(), Array() );
	$listaccesslist = explode( ",", $obsahtagu );
	foreach ( $listaccesslist as $accesslist ) {
		if ( strpos( $accesslist, "(ro)" ) !== false ) {
			$accesslist = trim( str_replace( "(ro)", "", $accesslist ) );
			$group = makeGroupArray( $accesslist );
			$accessgroup[1] = array_merge( $accessgroup[1], $group[0] );
			$accessgroup[1] = array_merge( $accessgroup[1], $group[1] );
		} else {
			$accesslist = trim( $accesslist );
			$group = makeGroupArray ($accesslist );
			$accessgroup[0] = array_merge( $accessgroup[0], $group[0] );
			$accessgroup[1] = array_merge( $accessgroup[1], $group[1] );
		}
	}
	return $accessgroup;
}

function makeGroupArray( $accesslist ) {
	/* Function returns array with two lists.
		First is list full access users.
		Second is list readonly users. */
	$userswrite = Array();
	$usersreadonly = Array();
	$users = getUsersFromPages( $accesslist );
	foreach ( array_keys( $users ) as $user ) {
		switch ( $users[$user] ) {
			case 'read':
				$usersreadonly[] = $user;
				break;
			case 'edit':
				$userswrite[] = $user;
				break;
		}
	}
	return array( $userswrite , $usersreadonly );
}

function displayGroups() {
	/* Function replace the tag <accesscontrol> and his content, behind info about a protection this the page */
	$style = "<p id=\"accesscontrol\" style=\"text-align:center;color:#BA0000;font-size:8pt\">";
	$text = wfMsg( 'accesscontrol-info' );
	$style_end = "</p>";
	$wgAllowInfo = $style . $text . $style_end;
	return $wgAllowInfo;
}

function getContentPage( $title ) {
	/* Function get content the page identified by title object from database */
	$Title = new Title();
	$gt = $Title->makeTitle( 0, $title );
	// create Article and get the content
	$contentPage = new Article( $gt, 0 );
	return $contentPage->fetchContent( 0 );
	}

function getTemplatePage( $template ) {
	/* Function get content the template page identified by title object from database */
	$Title = new Title();
	$gt = $Title->makeTitle( 10, $template );
	//echo '<!--';
	//print_r($gt);
	//echo '-->';
	// create Article and get the content
	$contentPage = new Article( $gt, 0 );
	return $contentPage->fetchContent( 0 );
	}

function getUsersFromPages( $skupina ) {
	/* Extracts the allowed users from the userspace access list */
	$allowedAccess = Array();
	$allow = Array();
	$Title = new Title();
	$gt = $Title->makeTitle( 0, $skupina );
	// create Article and get the content
	$groupPage = new Article( $gt, 0 );
	$allowedUsers = $groupPage->fetchContent( 0 );
	$groupPage = NULL;
	$usersAccess = explode( "\n", $allowedUsers );
	foreach  ($usersAccess as $userEntry ) {
		$userItem = trim( $userEntry );
		if ( substr( $userItem, 0, 1 ) == "*" ) {
			if ( strpos( $userItem, "(ro)" ) === false ) {
				$user = trim( str_replace( "*", "", $userItem ) );
				$allow[$user] = 'edit';
			} else {
				$user = trim( str_replace( "*", "", $userItem ) );
				$user = trim( str_replace( "(ro)", "", $user ) );
				$allow[$user] = 'read';
			}
		}
	}
	if ( is_array( $allow ) ) {
		$allowedAccess = $allow;
		unset( $allow );
	}
	return $allowedAccess;
}

function doRedirect( $info ) {
	/* make redirection for non authorized users */
	global $wgScript, $wgSitename, $wgOut;

	if ( ! $info ) {
	    $info = "No_access";
	    }
	if ( $info == "Only_sysop" ) {
		$target = wfMsg( 'accesscontrol-info-user' );
	} elseif ( $info == "No_anonymous" ) {
		$target = wfMsg( 'accesscontrol-info-anonymous' );
	} elseif ( $info == "Deny_anonymous") {
		$target = wfMsg( 'accesscontrol-edit-anonymous' );
	} elseif ( $info == "Deny_edit_list" ) {
		$target = wfMsg( 'accesscontrol-edit-users' );
	} else {
		$target = wfMsg( 'accesscontrol-info-deny' );
	}
	if ( isset( $_SESSION['redirect'] ) ) {
		// removing info about redirect from session after move..
		unset( $_SESSION['redirect'] );
	}
	header( "Location: " . $wgScript . "/" . $wgSitename . ":" . $target );
}

function fromTemplates( $string ) {
	global $wgUser, $wgAdminCanReadAll;
	// Vytažení šablon
	if ( strpos( $string, '{{' ) ) {
	    if ( substr( $string, strpos ( $string, '{{' ), 3 ) === '{{{' ) {
		    $start = strpos( $string, '{{{' );
		    $end = strlen( $string );
		    $skok = $start + 3;
		    fromTemplates( substr( $string, $skok, $end - $skok ) );
		} else {
		    $start = strpos( $string, '{{' );
		    $end = strpos( $string, '}}' );
		    $skok = $start + 2;
		    $templatepage = substr( $string, $skok, $end - $skok );
		    if ( strpos( $templatepage, '|' ) > 0) { 
			    $templatename = substr( $templatepage, 0, strpos( $templatepage, '|' ) );
			} else {
			    $templatename = $templatepage ;
			}
		    if ( substr( $templatename, 0, 1 ) === ':') {
			    // vložena stránka
			    $rights = allRightTags( getContentPage( substr( $templatename, 1 ) ) );
			} else {
			    // vložena šablona
			    $rights = allRightTags( getTemplatePage( $templatename ) );
			}
		    if ( is_array( $rights ) ) {
			if ( $wgUser->mId === 0 ) {
			    /* Redirection unknown users */
			    $wgActions['view'] = false;
			    doRedirect('accesscontrol-info-anonymous');
			    } else {
				if ( in_array( 'sysop', $wgUser->mGroups, true ) ) {
					if ( isset( $wgAdminCanReadAll ) ) {
						if ( $wgAdminCanReadAll ) {
							return true;
							}
						}
					}
				$users = accessControl( $rights['groups'] );
				if ( ! in_array( $wgUser->mName, $users[0], true ) ) {
					$wgActions['edit']           = false;
					$wgActions['history']        = false;
					$wgActions['submit']         = false;
					$wgActions['info']           = false;
					$wgActions['raw']            = false;
					$wgActions['delete']         = false;
					$wgActions['revert']         = false;
					$wgActions['revisiondelete'] = false;
					$wgActions['rollback']       = false;
					$wgActions['markpatrolled']  = false;
					if ( ! in_array( $wgUser->mName, $users[1], true ) ) {
						$wgActions['view']   = false;
						return doRedirect( 'accesscontrol-info-anonymous' );
						}
					}
				}
			}
		    fromTemplates( substr( $string, $end + 2 ) );
		}
	    }
    }


function allRightTags( $string ) {
	/* Function for extraction content tag accesscontrol from raw source the page */
	$contenttag  = Array();
	$starttag    = "<accesscontrol>";
	$endtag      = "</accesscontrol>";
	$redirecttag = "redirect";

	if ( ( mb_substr( trim( $string ), 0, 1 ) == "#" )
		&& ( stripos( mb_substr( trim( $string ), 1, 9 ), $redirecttag ) == "0" )
		) {
		/* Treatment redirects - content variable $string must be replaced over content the target page */
		$sourceredirecttag = mb_substr( $string, 0, strpos( $string, ']]' ) );
		$redirecttarget = trim( substr( $sourceredirecttag, strpos( $sourceredirecttag, '[[' ) + 2 ) );
		if ( strpos( $redirecttarget, '|' ) ) {
			$redirecttarget = trim( substr( $redirecttarget, 0, strpos( $redirecttarget, '|' ) ) );
		}
		$Title = new Title();
		$gt = $Title->makeTitle( 0, $redirecttarget );
		return allRightTags( getContentPage( $gt ) );
	}

	// Kontrola accesscontrol ve vložených šablonách a stránkách
	fromTemplates($string);

	$start = strpos( $string, $starttag );
	if ( $start !== false ) {
		$start += strlen( $starttag );
		$end = strpos( $string, $endtag );
		if ( $end !== false ) {
			$groupsString = substr( $string, $start, $end-$start );
			if ( strlen( $groupsString ) == 0 ) {
				$contenttag['end'] = strlen( $starttag ) + strlen( $endtag ); 
			} else {
				$contenttag['groups'] = $groupsString;
				$contenttag['end'] = $end + strlen( $endtag );
			}

			if( isset( $_SESSION['redirect'] ) ) {
				$_SESSION['redirect'] = $contenttag;
			} else {
				return $contenttag;
			}
		}
	} else {
		if( isset( $_SESSION['redirect'] ) ) {
			return $_SESSION['redirect'];
		} else {
			return false;
		}
	}
}

function hookUserCan( &$title, &$wgUser, $action, &$result ) {
	/* Main function control access for all users */
	global $wgActions, $wgAdminCanReadAll;
	if ( $wgUser->mId === 0 ) {
		/* Deny actions for all anonymous */
		$wgActions['edit']           = false;
		$wgActions['history']        = false;
		$wgActions['submit']         = false;
		$wgActions['info']           = false;
		$wgActions['raw']            = false;
		$wgActions['delete']         = false;
		$wgActions['revert']         = false;
		$wgActions['revisiondelete'] = false;
		$wgActions['rollback']       = false;
		$wgActions['markpatrolled']  = false;
		}

	$rights = allRightTags( getContentPage( $title->mDbkeyform ) );
	if ( is_array( $rights ) ) {
		if ( $wgUser->mId === 0 ) {
			/* Redirection unknown users */
			$wgActions['view'] = false;
			doRedirect( 'accesscontrol-info-anonymous' );
		} else {
			if ( in_array( 'sysop', $wgUser->mGroups, true ) ) {
				if ( isset( $wgAdminCanReadAll ) ) {
					if ( $wgAdminCanReadAll ) {
						return true;
					}
				}
			}				
			$users = accessControl( $rights['groups'] );
			if ( in_array( $wgUser->mName, $users[0], true ) ) {
				return true;
			} else {
				$wgActions['edit']           = false;
				$wgActions['history']        = false;
				$wgActions['submit']         = false;
				$wgActions['info']           = false;
				$wgActions['raw']            = false;
				$wgActions['delete']         = false;
				$wgActions['revert']         = false;
				$wgActions['revisiondelete'] = false;
				$wgActions['rollback']       = false;
				$wgActions['markpatrolled']  = false;
				if ( in_array( $wgUser->mName, $users[1], true ) ) {
					return true;
				} else {
					$wgActions['view']   = false;
					return doRedirect( 'accesscontrol-info-anonymous' );
				}
			}
		}
	} else {
		return true;
	}
}

?>
