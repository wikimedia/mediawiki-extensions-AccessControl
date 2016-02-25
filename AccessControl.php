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

if( !defined( 'MEDIAWIKI' ) ) {
	echo ( "This file is an extension to the MediaWiki software and cannot be used standalone.\n" );
	die();
}

// sysop users can read all restricted pages
$wgAdminCanReadAll = true;
$wgAccessControlRedirect = true;
$wgAccessToHistory = false;

$wgExtensionCredits['parserhook'][] = array(
	'path'                  => __FILE__,
	'name'                  => 'AccessControl',
	'author'                => array( '[https://www.mediawiki.org/wiki/m:User:Want Aleš Kapica]' ),
	'url'                   => 'http://www.mediawiki.org/wiki/Extension:AccessControl',
	'version'               => '2.5.1',
	'descriptionmsg'        => 'accesscontrol-desc'
);

$wgHooks['ParserFirstCallInit'][] = 'wfAccessControlExtension' ;

$dir = dirname( __FILE__ ) . '/';
$wgMessagesDirs['AccessControl'] = __DIR__ . '/i18n';


//Hook the userCan function for bypassing the cache
$wgHooks['userCan'][] = 'hookUserCan';

//Hook the UnknownAction function for information user about restrictions
$wgHooks['UnknownAction'][] = 'onUnknownAction' ;

function onUnknownAction ( $action, Page $article ) {
	global $wgOut;
	switch ( $action ) {
		default:
			$wgOut->setPageTitle( $article->getTitle() . "->" . $action );
			$wgOut->addWikiText( wfMessage( 'accesscontrol-actions-deny' )->text());
	}
	return false;
}

function wfAccessControlExtension( Parser $parser ) {
	/* This the hook function adds the tag <accesscontrol> to the wiki parser */
	$parser->setHook( "accesscontrol", "doControlUserAccess" );
	return true;
}

function doControlUserAccess( $input, array $args, Parser $parser, PPFrame $frame ) {
	/* Funcion called by wfAccessControlExtension */
	return displayGroups();
}

function accessControl( $tagContent ){
	$accessgroup = Array( Array(), Array() );
	$listaccesslist = explode( ",", $tagContent );
	foreach ( $listaccesslist as $accesslist ) {
		if ( strpos( $accesslist, "(ro)" ) !== false ) {
			$accesslist = trim( str_replace( "(ro)", "", $accesslist ) );
			$group = makeGroupArray( $accesslist );
			$accessgroup[1] = array_merge( $accessgroup[1], $group[0] );
			$accessgroup[1] = array_merge( $accessgroup[1], $group[1] );
		} else {
			$accesslist = trim( $accesslist );
			$group = makeGroupArray ( $accesslist );
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
	return array( $userswrite, $usersreadonly );
}

function displayGroups() {
	/* Function replace the tag <accesscontrol> and his content, behind info about a protection this the page */
	$style = "<p id=\"accesscontrol\" style=\"text-align:center;color:#BA0000;font-size:8pt\">";
	$text = wfMessage( 'accesscontrol-info' )->text();
	$style_end = "</p>";
	$wgAllowInfo = $style . $text . $style_end;
	return $wgAllowInfo;
}

function getContentPage( $namespace, $title ) {
	/* Function get content the page identified by title object from database */
	$Title = new Title();
	$gt = $Title->makeTitle( $namespace, $title );
	if ( method_exists( 'WikiPage', 'getContent' ) ) {
		$contentPage = new WikiPage( $gt );
		if ( $contentPage->getContent() != NULL ) {
			return $contentPage->getContent()->getNativeData();
		}
	} else {
		//echo print_r($gt);
		// create Article and get the content
		$contentPage = new Article( $gt, 0 );
		return $contentPage->fetchContent( 0 );
	}
}

function getTemplatePage( $template ) {
	/* Function get content the template page identified by title object from database */
	$Title = new Title();
	$gt = $Title->makeTitle( 10, $template );
	if ( method_exists( 'WikiPage', 'getContent' ) ) {
		$contentPage = new WikiPage( $gt );
		return $contentPage->getContent()->getNativeData();
	} else {
		// create Article and get the content
		$contentPage = new Article( $gt, 0 );
		return $contentPage->fetchContent( 0 );
	}
}

function getUsersFromPages( $group ) {
	/* Extracts the allowed users from the userspace access list */
	$allowedAccess = Array();
	$allow = Array();
	$Title = new Title();
// Remark: position to add code to use namespace from mediawiki
	$gt = $Title->makeTitle( 0, $group );
	if ( method_exists( 'WikiPage', 'getContent' ) ) {
		$groupPage = new WikiPage( $gt );
		$allowedUsers = $groupPage->getContent()->getNativeData();
	} else {
		// create Article and get the content
		$groupPage = new Article( $gt, 0 );
		$allowedUsers = $groupPage->fetchContent( 0 );
	}
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
	global $wgScript, $wgSitename, $wgOut, $wgAccessControlRedirect;
	if ( ! $info ) {
	    $info = "No_access";
	    }
	if ( isset( $_SESSION['redirect'] ) ) {
		// removing info about redirect from session after move..
		unset( $_SESSION['redirect'] );
	}
	$wgOut -> clearHTML() ;
	$wgOut -> prependHTML( wfMessage( 'accesscontrol-info-box' ) -> text() );
	if ( $wgAccessControlRedirect ) {
		header( "Location: " . $wgScript . "/" . $wgSitename . ":" . wfMessage( $info )->text() );
	}
}

function fromTemplates( $string ) {
	global $wgUser, $wgAdminCanReadAll;
	// Template extraction
	if ( strpos( $string, '{{' ) >= 0 ) {
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
			if ( substr( $templatepage, 0, 1 ) == '{' ) {
				// The check of included code
				$rights = fromTemplates( $templatepage );
			} elseif ( substr( $templatepage, 0, 1 ) == ':' ) {
				// The check of included page
				$rights = allRightTags( getContentPage( 0, substr( $templatepage, 1 ) ) );
			} elseif ( ctype_alnum( substr( $templatepage, 0, 1 ) )) {
				// The check of included template
				if ( strpos( $templatepage, '|' ) > 0) {
					$templatename = substr( $templatepage, 0, strpos( $templatepage, '|' ) );
					$rights = allRightTags( getContentPage( 10, $templatename ) );
				} else {
					$rights = allRightTags( getContentPage( 10, $templatepage ) );
				}
			} else {
				// echo "The end of work with code of article";
			}
			if ( isset( $rights ) ) {
				if ( is_array( $rights ) ) {
					if ( $wgUser->mId === 0 ) {
						/* Redirection unknown users */
						$wgActions['view'] = false;
						doRedirect('accesscontrol-move-anonymous');
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
								return doRedirect( 'accesscontrol-move-users' );
							}
						}
					}
				}
			}
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
		return allRightTags( getContentPage( $gt->getNamespace(), $gt ) );
	}

	// The control of included pages and templates on appearing of accesscontrol tag
	fromTemplates( $string );
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
	global $wgActions, $wgAdminCanReadAll, $wgRequest, $wgAccessToHistory;
	if ( $wgUser->mId === 0 ) {
		/* Deny actions for all anonymous */
		if ( $wgAccessToHistory == false ) {
			if ($wgRequest->getText( 'type' ) == 'revision' || $wgRequest->getText( 'action' ) == 'history' ) {
				$wgActions['view'] = false;
				return doRedirect( 'accesscontrol-redirect-anonymous' );
			}
		}
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

	$rights = allRightTags( getContentPage( $title->getNamespace(), $title->mDbkeyform ) );
	if ( is_array( $rights ) ) {
		if ( $wgUser->mId === 0 ) {
			/* Redirection unknown users */
			$wgActions['view'] = false;
			doRedirect( 'accesscontrol-redirect-anonymous' );
		} else {
			if ( in_array( 'sysop', $wgUser->getGroups(), true ) ) {
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
					return doRedirect( 'accesscontrol-redirect-users' );
				}
			}
		}
	} else {
		return true;
	}
}
