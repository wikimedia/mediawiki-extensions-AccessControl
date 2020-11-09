<?php

class AccessControlHooks {


	/**
	 * Tag <accesscontrol> must be registered to the Parser. It is need,
	 *  because if the tag not in register, can't be replaced content of
	 *  this tag element on the page.
	 *
	 * @param Parser $parser instance of Parser
	 * @return bool true
	 */
	public static function accessControlExtension(
		Parser $parser
		) {
//		self::printDebug( microtime(true) . ' accessControlExtension remove tag accesscontrol from content of page - if exists' ); // DEBUG TIMESTAMP
		$parser->setHook( 'accesscontrol', [ 'AccessControlHooks', 'displayInfo' ] );
		return true;
	}


	/**
	 * Function for backward comaptibility. If page is protect by tag <accesscontrol>
	 *  must return empty string. If return null, is displayed the message ID string
	 *  instead of the tag content, i.e.: '"`UNIQ--accesscontrol-00000000-QINU`"'
	 *  And if return true, may be displayed value 1.
	 *
	 * @return string (empty)
	 */
	public static function displayInfo() {
		return (string)'';
	}


	/**
	 * Function is called before is done database query for export content of page.
	 *  Access for unauthorized (anonymous) users is deny ever (LIMIT is set 0). User,
	 *  that can read content of this page may do export only last revision of this
	 *  page (without history). Authorized user, with allow access or 'sysop' can
	 *  do export without limits.
	 *
	 * This hook catches every attempt to get unauthorized content by the export.
	 *
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/ModifyExportQuery
	 * @since 1.16
	 *
	 * @param string $cond Name and namespace of target page which is tested for
	 *  access rights of user to export
	 * @param array $opts Limit for summary count of the hits (is modify)
	 * @param array $join Parameters of join (is modify)
	 */
	public static function onModifyExportQuery(
		$db,
		&$tables,
		&$cond,
		&$opts,
		&$join
		) {
		global $wgQueryPages;
		/* If is page protected, do skip and if user has only read
		    access, return only last revisioni - without history */
//		$start = microtime(true); // START DEBUG TIMESTAMP
		$result = self::controlExportPage( $cond );
//		self::printDebug( $cond ); // END DEBUG TIMESTAMP
//		self::printDebug( $result ); // END DEBUG TIMESTAMP
		switch ( $result ) {
			case 1 :
//				self::printDebug( microtime(true) . ' onModifyExportQuery export ok '); // END DEBUG TIMESTAMP
				break;
			case 2 : $opts['LIMIT'] = 1;
//				self::printDebug( microtime(true) . ' onModifyExportQuery set version limit '); // END DEBUG TIMESTAMP
				$join['revision'][1] = 'page_id=rev_page AND page_latest=rev_id';
				break;
			default :
//				self::printDebug( microtime(true) . ' onModifyExportQuery set limit zero' . $result ); // END DEBUG TIMESTAMP
				$opts['LIMIT'] = 0;
				break;
		}
//		self::printDebug( $start . ' onModifyExportQuery ' . $cond . ' + ' . ( microtime(true) - $start ) ); // END DEBUG TIMESTAMP
	}


	/**
	 * Function is called before applied the parser to raw wiki code of page.
	 *  This a hook is activated after every database query, before next processing
	 *  the raw code of page. Therefore is used global variable $wgVerifyPage to
	 *  ensure that one and the same page is not repeatedly controlled.
	 *  Content of this variable is array, what contains lastid for all pages of
	 *  current process. Items to this array add functions onuserCan (for the input
	 *  page) and getContentPage (transclusioned a pages)
	 *
	 * This hook can replace hook onuserCan()
	 *
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/ParserBeforeStrip
	 * @since 1.5
	 *
	 * @param Parser $parser Object of current input page
	 * @text string $text Chunk of wikicode for tranclusion into page
	 */
	public static function onParserBeforeStrip(
		&$parser,
		&$text,
		&$strip_state
		) {
		global $wgVerifyPage;


//		$start = microtime(true) ; // START DEBUG TIMESTAMP
		$articleName	= $parser->mTitle->mTextform;
		$articleNS	= $parser->mTitle->mNamespace;
		$articleLastRev	= $parser->mTitle->getLatestRevId();
//		self::printDebug( "$start onParserBeforeStrip start verify access to lastrevision=\"$articleLastRev\" of title=\"$articleName\" ns=\"$articleNS\"" ); // INFO DEBUG TIMESTAMP
		if ( is_array( $wgVerifyPage ) ) {
			if ( array_key_exists(  $articleLastRev, $wgVerifyPage ) ) {
				if ( ! $wgVerifyPage[ $articleLastRev ] ) {
					/* In array $wgVerify is revision ID with value false, it is chunk of content what is deny for the current user! */
//					self::printDebug( "$start onParserBeforeStrip GET OUT! $articleLastRev" ); // INFO DEBUG TIMESTAMP
					return false;
				}
			}
		}
		self::anonymousDeny();
		$rights = self::allRightTags( $text );
		if ( ! ( empty( $rights[VIEW] ) && empty( $rights[EDIT] ) ) ) {
			switch ( self::testRightsArray( $rights ) ) {
				case 1 :
					// chunk is without protection
					$wgVerifyPage[ $articleLastRev ] = true;
					break;
				case 2 :
					// chunk is to read
					self::readOnlyUser();
					self::denyRead();
					$text='{{int:accesscontrol-readonly}}' . $text;
					$wgVerifyPage[ $articleLastRev ] = false;
					break;
				default :
					// chunk is deny
					self::readOnlyUser();
					self::denyRead();
					$text='{{int:accesscontrol-info}}';
					self::doRedirect( 'accesscontrol-redirect-users' );
					$wgVerifyPage[ $articleLastRev ] = false;
					break;
			}
		}
		// Je-li vypnuté přesměrování, pokračuje ve skriptu...
		// Use only for tests of performace
//		self::printDebug($wgVerifyPage); // DEBUG
//		self::printDebug( "$start onParserBeforeStrip FREE lastrevision=\"$articleLastRev\" of title=\"$articleName\" ns=\"$articleNS\" + " . ( microtime(true) - $start ) ); // END DEBUG TIMESTAMP
	}


	/**
	 * Function allow modify result of find by control content pages from hits and user rights.
	 *
	 * This hook prevents the content of the protected page from being compromised while
	 *  searching.
	 *
	 * @see  https://www.mediawiki.org/wiki/Manual:Hooks/ShowSearchHit
	 * @since 1.21
	 *
	 * @param $result
	 * @param string $extract If current user can't access to content of the page
	 *  from result, is extract from the hit replaced by the info message.
	 */
	public static function onShowSearchHit(
		$searchPage,
		$result,
		$terms,
		&$link,
		&$redirect,
		&$section,
		&$extract,
		&$score,
		&$size,
		&$date,
		&$related,
		&$html
		) {
//		$start = microtime(true); // START DEBUG TIMESTAMP
		if ( $result ) {
			$page = $result->getTitle();
			$content = self::getContentPage( $page->mNamespace, $page->mTextform );
			$rights = self::allRightTags( $content );
			if ( !( empty( $rights[VIEW] ) && empty( $rights[EDIT] ) ) ) {
				switch ( self::testRightsArray( $rights ) ) {
					case 1 :
					case 2 :
						break;
					default :
						// is false
						$extract = wfMessage( 'accesscontrol-actions-deny' )->text();
						break;
				}
			}
		}
//		self::printDebug( $start . ' onShowSearchHit' . ' title="' . $page->mTextform . '" ns="' . $page->mNamespace . '" + ' . ( microtime(true) - $start ) ); // END DEBUG TIMESTAMP
	}


	/**
	 * Main function, which control access rights for all users.
	 * @see  https://www.mediawiki.org/wiki/Manual:Hooks/userCan
	 *
	 * @param Title $title
	 */
	public static function onuserCan(
		&$title,
		&$wgUser,
		$action,
		&$result
		) {
		global $wgVerifyPage;
		$articleName	= $title->mTextform;
		$articleNS	= $title->mNamespace;
		$userName	= $wgUser->mName;
//		$start = microtime( true ); // START DEBUG TIMESTAMP
		if ( is_array( $wgVerifyPage ) ) {
			if ( array_key_exists( $title->getLatestRevID(), $wgVerifyPage ) ) {
//				self::printDebug( "$start onUserCan skip title=\"$articleName\" ns=\"$articleNS\" for current username \"$userName\" because is verified for now" ); // INFO DEBUG TIMESTAMP
				return true;
			}
		} else {
			$wgVerifyPage = [];
		}
//		self::printDebug( "$start onUserCan start verify access to title=\"$articleName\" ns=\"$articleNS\" for current username \"$userName\"" ); // INFO DEBUG TIMESTAMP

		if ( $articleName == wfMessage( 'accesscontrol-action-deny' )->text()
			&& $articleNS == $wgSitename ) {
			return true;
		}

		self::anonymousDeny();
// Proč se volá controlExportPage bez parametrů?
//		self::controlExportPage();
		// return array of users & rights
		$rights = self::allRightTags(
			self::getContentPage(
				$title->getNamespace(),
				$title->mDbkeyform
			)
		);
//		$wgVerifyPage[ $title->getLatestRevID() ] = true;
		self::userVerify( $rights );
//		self::printDebug( "$start onUserCan title=\"$articleName\" ns=\"$articleNS\" + " . ( microtime( true ) - $start ) ); // END DEBUG TIMESTAMP
	}


	/**
	 * Main function for get array of rights from content of page (accesslist)
	 *
	 * @param string $string
	 *
	 * @return array $allow
	 */
	private static function allRightTags(
		$string
		) {
		global $wgAccessControlNamespaces;
		if ( ! defined('PREG_UNMATCHED_AS_NULL') ) {
			// Constant is predefined from PHP versio 7.2.0
			define( 'PREG_UNMATCHED_AS_NULL', 512 );
		}
		if ( ! defined('PROTECTEDBY') ) {
			define( 'PROTECTEDBY', 'isProtectedBy' );
			define( 'READGROUPS', 'readOnlyAllowedGroups' );
			define( 'EDITGROUPS', 'editAllowedGroups' );
			define( 'READERS', 'readOnlyAllowedUsers' );
			define( 'VIEW', 'visitors' );
			define( 'EDITORS', 'editAllowedUsers' );
			define( 'EDIT', 'editors' );
		}

//		self::printDebug( $string ); // INFO DEBUG input string is raw content of page
		/* Redirect */
		preg_match(
			'/\#REDIRECT +\[\[(.*?)[\]\]|\|]/i',
			$string,
			$match,
			PREG_UNMATCHED_AS_NULL
			);
		if ($match) {
			$array = self::getAccessListCanonicalTarget( $match[1] );
			if ($array) {
				$rights = self::allRightTags( self::getContentPage( $array['ns'], $array['title'] ) );
				self::anonymousDeny();
				self::userVerify($rights);
//				self::printDebug($rights); // INFO DEBUG
			}
		}
		$allow = [ EDIT => [], VIEW => [] ];
		preg_match_all(
			'/(?J)(?<match>\{\{[^\}]+(.*)\}\})|(?<match>\<accesscontrol\>(.*)\<\/accesscontrol\>)/',
			$string,
			$matches,
			PREG_PATTERN_ORDER
			);
		foreach( $matches[0] as $pattern ) {
			/* Transclusions of page, which is not from template namespace */
			if ( substr( $pattern, 0, 3 ) === '{{:' ) {
				// transclusion any page
				preg_match(
					'/\{\{:(.*?)[\}\}|\|]/',
					$pattern,
					$include,
					PREG_UNMATCHED_AS_NULL
					);
				if ($include) {
					$array = self::getAccessListCanonicalTarget( $include[1] );
					if ($array) {
						$rights = self::allRightTags( self::getContentPage( $array['ns'], $array['title'] ) );
						self::anonymousDeny();
						self::userVerify($rights);
//						self::printDebug( $rights ); // INFO DEBUG
					}
				}
			}
			if ( substr( $pattern, 0, 3 ) === '{{{' ) {
				preg_match(
					'/\{\{\{(.*?)\}\}\}/',
					$pattern,
					$include,
					PREG_UNMATCHED_AS_NULL
					);
				if ($include) {
					switch ( $include[1] ) {
						case ( preg_match( "/^[0-9]/", $include[1] ) ? true : false ) :
							// číslovaná proměnná
//							self::printDebug( $include ); // INFO DEBUG
							break;
						case ( preg_match( "/\|/", $include[1] ) ? true : false ) :
							// parametrizovaná šablona
//							self::printDebug( $include ); // INFO DEBUG
							break;
						default:
//							self::printDebug( $include ); // INFO DEBUG
//							break;
					}
				}
			}
			if ( substr( $pattern, 0, 3 ) === '{{#' ) {
				preg_match(
					'/\{\{\#(.*?)\}\}/',
					$pattern,
					$include,
					PREG_UNMATCHED_AS_NULL
					);
				if ($include) {
					switch ( $include[1] ) {
						case ( preg_match( "/^[a-z]+/i", $include[1] ) ? true : false ) :
							// interní funkce
//							self::printDebug($include); // INFO DEBUG
							break;
					}
				}
			}
			/* Template transclusion */
			if ( substr( $pattern, 0, 2 ) === '{{' ) {
				// transclusion template
				preg_match(
					'/\{\{(.*?)[\}\}|\|]/',
					$pattern,
					$include,
					PREG_UNMATCHED_AS_NULL
					);
				if ($include) {
					$rights = self::allRightTags( self::getContentPage( 10, trim($include[1]) ) );
					self::anonymousDeny();
					self::userVerify($rights);
//					self::printDebug( $rights ); // INFO DEBUG
				}
			}
			switch ( substr( mb_strtolower( $pattern, 'UTF-8' ), 0, 15 ) ) {
				case '<accesscontrol>' :
					/* Protected by tag */
					$allow = self::earlySyntaxOfRights( trim(str_replace( '</accesscontrol>', '', str_replace( '<accesscontrol>', '', $pattern ) ) ) );
/* Array of members is based by content of the element accesscontrol */
//					self::printDebug( $allow ); // INFO DEBUG
					break;
				default :
					if (
//						strpos( $pattern, 'isProtectedBy') ||
						strpos( $pattern, PROTECTEDBY ) ||
						strpos( $pattern, READERS) ||
						strpos( $pattern, EDITORS) ||
						strpos( $pattern, READGROUPS) ||
						strpos( $pattern, EDITGROUPS)
					   ) {
						/* Protected by options */
						$options = array_map( 'trim', explode( '|' , $pattern ) );
						foreach ( $options as $string ) {
//							self::printDebug($string); // INFO DEBUG
							if ( is_integer( strpos( $string, 'isProtectedBy' ) ) ) {
								/* page is protected by list of users */
								$groups = self::membersOfGroup($string);
								if ( array_key_exists( PROTECTEDBY, $groups) ) {
									foreach ( $groups[PROTECTEDBY] as $group ) {
										$accesslist = self::getAccessListCanonicalTarget( $group );
//										self::printDebug( $accesslist ); // INFO DEBUG
										if ( $accesslist['ns'] == 0 ) {
											foreach ($wgAccessControlNamespaces as $ns) {
												$array = self::getContentPageNew( $group, $ns);
												if ( array_key_exists( EDIT, $array) ) {
													foreach( array_keys($array[EDIT]) as $user) {
														$allow[EDIT][$user] = true;
													}
												}
												if ( array_key_exists( VIEW, $array) ) {
													foreach( array_keys($array[VIEW]) as $user) {
														$allow[VIEW][$user] = true;
													}
												}
											}
										} else {
											$array = self::getContentPageNew( $accesslist['title'], $accesslist['ns'] );
											if ( array_key_exists( EDIT, $array) ) {
												foreach( array_keys($array[EDIT]) as $user) {
													$allow[EDIT][$user] = true;
												}
											}
											if ( array_key_exists( VIEW, $array) ) {
												foreach( array_keys($array[VIEW]) as $user) {
													$allow[VIEW][$user] = true;
												}
											}
										}
									}
								}
/* isProtectedBy */
//								self::printDebug( $allow ); // INFO DEBUG
							}
							if ( is_integer( strpos ( $string, READGROUPS ) ) || is_integer( strpos ( $string, READERS ) ) ) {
								/* readonly access - stronger then rights from isProtectedby */
								$readers = self::membersOfGroup($string);
								if ( array_key_exists( READGROUPS, $readers ) ) {
									foreach( $readers[READGROUPS] as $group ) {
										$accesslist = self::getAccessListCanonicalTarget( $group );
//										self::printDebug( $accesslist ); // INFO DEBUG
										if ( $accesslist['ns'] == 0 ) {
											foreach ($wgAccessControlNamespaces as $ns) {
												$array = self::getContentPageNew( $group, $ns);
												if ( array_key_exists( EDIT, $array) ) {
													foreach( array_keys($array[EDIT]) as $user) {
														$allow[EDIT][$user] = false;
														$allow[VIEW][$user] = true;
													}
												}
												if ( array_key_exists( VIEW, $array) ) {
													foreach( array_keys($array[VIEW]) as $user) {
														$allow[VIEW][$user] = true;
													}
												}
											}
										} else {
											$array = self::getContentPageNew( $accesslist['title'], $accesslist['ns']);
											if ( array_key_exists( EDIT, $array) ) {
												foreach( array_keys($array[EDIT]) as $user) {
													$allow[EDIT][$user] = false;
													$allow[VIEW][$user] = true;
												}
											}
											if ( array_key_exists( VIEW, $array) ) {
												foreach( array_keys($array[VIEW]) as $user) {
													$allow[VIEW][$user] = true;
												}
											}
										}
									}
								}
/*  readOnlyAllowedGroups */
//								self::printDebug( $allow ); // INFO DEBUG
								/* readonly access - stronger then rights from isProtectedby */
								if ( array_key_exists( READERS, $readers ) ) {
									foreach( $readers[READERS] as $user ) {
										if ( array_key_exists( EDIT, $allow ) ) {
											if ( array_key_exists( $user, $allow[EDIT] ) ) {
												/* vypínám právo k editaci */
												$allow[EDIT][$user] = false;
											}
										}
										if ( array_key_exists(VIEW, $allow) ) {
											$allow[VIEW][$user] = true;
										}
									}
								}
/* readOnlyAllowedUsers */
//								self::printDebug( $allow ); // INFO DEBUG
							}
							if ( is_integer( strpos( $string, EDITORS ) ) || is_integer( strpos( $string, EDITGROUPS ) ) ) {
								/* edit access - stronger then rights from isProtectedby, and rights from readonly options */
								$editors = self::membersOfGroup($string);
								if ( array_key_exists( EDITGROUPS, $editors ) ) {
									foreach( $editors[EDITGROUPS] as $group ) {
										$accesslist = self::getAccessListCanonicalTarget( $group );
//										self::printDebug( $accesslist ); // INFO DEBUG
										if ( $accesslist['ns'] == 0 ) {
											foreach ($wgAccessControlNamespaces as $ns) {
												$array = self::getContentPageNew( $group, $ns);
												if ( array_key_exists( VIEW, $array) ) {
													foreach( array_keys($array[VIEW]) as $user) {
														$allow[EDIT][$user] = true;
													}
												}
											}
										} else {
											$array = self::getContentPageNew( $accesslist['title'], $accesslist['ns']);
											if ( array_key_exists( VIEW, $array) ) {
												foreach( array_keys($array[VIEW]) as $user) {
													$allow[EDIT][$user] = true;
												}
											}
										}
									}
/* editAllowedGroups */
//								self::printDebug( $allow ); // INFO DEBUG
								}
								if ( array_key_exists( EDITORS, $editors ) ) {
									/* přidat do seznam editorů */
									foreach( $editors[EDITORS] as $user ) {
										$allow[EDIT][$user] = true;
									}
								}
/* editAllowedUsers */
//								self::printDebug( $allow ); // INFO DEBUG
							}
							/* ignore other options or params */
						}
/* Array of rights is set by template options */
//						self::printDebug( $allow ); // INFO DEBUG
					} elseif ( strpos( $pattern, 'accesscontrol') > 0 ) {
						/* If is string accesscontrol in $pattern before bar,
						 *  it's a part of template name and the content of
						 *  the first parameter of this template is accepted
						 *  as alternative syntax for tag accesscontrol.
						 */
//						self::printDebug($pattern); // INFO DEBUG
						$pos = ( strpos( $pattern, '|' ) );
						if ( $pos > strpos( $pattern, 'accesscontrol') ) {
							$retezec = trim( substr( $pattern, $pos + 1 ) );
							if ( strpos( $retezec, '|' ) ) {
								$members = trim( substr( $retezec, 0, strpos( $retezec, '|' ) ) );
							} else {
								if ( strpos( $retezec, '}' ) ) {
									$members = trim( substr( $retezec, 0, strpos( $retezec, '}' ) ) );
								}
							}
							if ( !strpos( $members, '=') ) {
								/* {{Template name with accesscontrol string | accesslist_X, userA, userB | option = … }} */
								$allow = self::earlySyntaxOfRights( $members );
							}
/* Array of members is generated by first parameter of template with accesscontrol string in name */
//						self::printDebug( $allow ); // INFO DEBUG
						}
					}
			}
		}
	/* Array has 2 keys with arays of:
	    editors - member can do all (if have value true)
	    visitors - member can do only read
	*/
//		self::printDebug( $allow ); // INFO DEBUG
		return $allow;
	}


	/**
	 * Preventive deny rights for anonymous users.
	 */
	private static function anonymousDeny() {
		global $wgActions, $wgUser, $wgAnonymousUser, $wgRequest, $wgAccessToHistory;
		if ( ! $wgAnonymousUser ) {
			if ( $wgUser->mId === 0 ) {
				$wgActions['submit'] = false;
				$wgActions['info'] = false;
				$wgActions['raw'] = false;
				$wgActions['delete'] = false;
				$wgActions['revert'] = false;
				$wgActions['revisiondelete'] = false;
				$wgActions['rollback'] = false;
				$wgActions['markpatrolled'] = false;
				$wgActions['formedit'] = false;
//				$wgActions['edit'] = false;

				if ( $wgAccessToHistory == true ) {
					if (  $wgRequest->getText( 'action' ) == 'history' ) {
//						self::printDebug( 'anonymous user can view history of page' ); // DEBUG INFO
					} elseif ( $wgRequest->getText( 'diff' ) >= 0 ) {
//						self::printDebug( 'anonymous user can view diferences of page' ); // DEBUG INFO
					} elseif ( $wgRequest->getText( 'action' ) == 'edit'
						&& $wgRequest->getText( 'oldid' ) >= 0 ) {
//						self::printDebug( 'anonymous user can view source of page' ); // DEBUG INFO
					} elseif ( ( $wgRequest->getText( 'direction' ) == 'prev'
							|| $wgRequest->getText( 'direction' ) == 'next' )
								&& $wgRequest->getText( 'oldid' ) >= 0 ) {
//						self::printDebug( 'anonymous user can view differences of page' ); // DEBUG INFO
					} else {
						$wgActions['edit'] = false;
					}
				} else {
					if ( ! empty( $wgRequest->getText('action') ) ) {
//self::printDebug( $wgRequest );
						if (  $wgRequest->getText('action') != 'search' ) {
							$wgActions['edit'] = false;
							$wgActions['view'] = false;
							$wgActions['history'] = false;
							return self::doRedirect( 'accesscontrol-redirect-anonymous' );
						}
					} elseif ( $wgRequest->getText('direction') == 'prev' || $wgRequest->getText('direction') == 'next' )  {
						return self::doRedirect( 'accesscontrol-redirect-anonymous' );
					} elseif ( ! empty( $wgRequest->getText('diff') ) )  {
						return self::doRedirect( 'accesscontrol-redirect-anonymous' );
					}
				}
//				self::printDebug( microtime(true) . ' anonymousDeny variable $wgAnonymousUser is set true' ); // DEBUG TIMESTAMP
				$wgAnonymousUser = true;
			} else {
//				self::printDebug( microtime(true) . ' anonymousDeny variable $wgAnonymousUser is set false' ); // DEBUG TIMESTAMP
//				$wgAnonymousUser = false;
			}
		}
		return;
	}


	/**
	 * Function is called only if current user want do export page, which may be
	 *  protected by AccessControl.
	 *
	 * @param string $string
	 *
	 * @return int|bool
	 */
	private static function controlExportPage( $string = "page_namespace=0 AND page_title='test-protectbyoption'") {
		/* "page_namespace=8 AND page_title='fuckoff'" */
		global $wgUser, $wgAdminCanReadAll;
		if ( $wgUser->mId === 0 ) {
			/* Deny export for all anonymous */
//			self::printDebug( microtime(true) . ' controlExportPage deny'); // INFO DEBUG TIMESTAMP
			return false;
		}
		preg_match(
			'/page_namespace=(.*?) AND page_title=\'(.*?)\'/',
			$string,
			$match,
			PREG_UNMATCHED_AS_NULL
			);
		if ( $match ) {
			$rights = self::allRightTags( self::getContentPage(
				$match[1],
				$match[2]
			) );
			if ( empty( $rights[VIEW] ) && empty( $rights[EDIT] ) ) {
				/* page is free */
//				self::printDebug( microtime(true) . ' controlExportPage view'); // INFO DEBUG TIMESTAMP
				return 1;
			}
			if ( in_array( 'sysop', $wgUser->getGroups(), true ) ) {
				if ( isset( $wgAdminCanReadAll ) ) {
					if ( $wgAdminCanReadAll ) {
						/* admin can be all */
//						self::printDebug( microtime(true) . ' controlExportPage admin'); // INFO DEBUG TIMESTAMP
						return 1;
					}
				}
			}
			if ( empty( $wgUser->mName ) ) {
				// for anonymous query by api is empty
//				self::printDebug( microtime(true) . ' controlExportPage anonymous'); // INFO DEBUG TIMESTAMP
				return false;
			}
			if ( array_key_exists( $wgUser->mName, $rights[EDIT] ) || array_key_exists( $wgUser->mName, $rights[VIEW] ) ) {
				/* readonly user */
//				self::printDebug( microtime(true) . ' controlExportPage readonly user'); // INFO DEBUG TIMESTAMP
				return 2;
			} else {
//				self::printDebug( microtime(true) . ' controlExportPage false?'); // INFO DEBUG TIMESTAMP
				return false;
			}
		}
	}


	/**
	 * Deny rights to action 'view' for current user.
	 */
	private static function denyRead() {
		global $wgActions, $wgUser;
//		self::printDebug( microtime(true) . ' denyRead' ); // DEBUG TIMESTAMP
		$wgActions['view'] = false;
		return;
	}


	/**
	 * Function stops further processing the page and redirect
	 *  unathorized user to the page with info about protection
	 *
	 *  If you want view target of redirect, uncomment line with
//	 *  string DEBUG TIMESTAMP, and see on top HTML source protect
	 *  page for info.
	 *
	 * @param string $info String with reason of redirection,
	 *  which is printed in localize form into information page
	 */
	private static function doRedirect(
		$info
		) {
		global $wgScript, $wgSitename, $wgOut, $wgAccessControlRedirect;
		if ( !$info ) {
			$info = "No_access";
		}
		if ( isset( $_SESSION['redirect'] ) ) {
			// removing info about redirect from session after move..
			unset( $_SESSION['redirect'] );
		}
		$wgOut->clearHTML();
		$wgOut->prependHTML( wfMessage( 'accesscontrol-info-box' )->text() );
		if ( $wgAccessControlRedirect == true ) {
			header( "Location: " . $wgScript . "/" . $wgSitename . ":" . wfMessage( $info )->text() );
			exit();
		} else {
//			self::printDebug( microtime(true) . ' STOP! doRedirect to ' . $wgScript . "/" . $wgSitename . ":" . wfMessage( $info )->text() ); // DEBUG TIMESTAMP
			return;
		}
		return;
	}


	/**
	 *
	 * @param string $string
	 *
	 * @return array $allow
	 */
	private static function earlySyntaxOfRights( $string ) {
		global $wgAccessControlNamespaces, $wgUser;
		/* u staršího typu syntaxe se mohly vyskytnout zároveň
		- nejprve test uživatelské skupiny MediaWiki
		- pak test na shodu uživatelského jména
		- seznamy
		Nezkoumají se všechna jména.
		Výsledek se vrací ihned po nastavení
		*/
		$allow = [ EDIT => [], VIEW => [] ];
		$MWgroups = User::getAllGroups();
		foreach( explode( ',', $string ) as $title ) {
			//zkontrolovat, jestli není readonly
			$item = self::oldSyntaxTest( $title );
			if ( is_array( $item ) ) {
				/* Může to být seznmam uživatelů starého typu */
//				$skupina = self::testRightsOfMember($item[0]);
//				self::printDebug( $item ); // INFO DEBUG
				/* Může to být seznmam uživatelů nového typu */
				foreach ( $wgAccessControlNamespaces as $ns ) {
					$array = self::getContentPageNew( $item[0], $ns );
//					self::printDebug( $array ); // INFO DEBUG
					if ( empty( $array ) ) {
						foreach ( $MWgroups as $mwgroup ) {
							if ( $item[0] === $mwgroup ) {
								foreach ( $wgUser->getEffectiveGroups() as $group ) {
									if ( $group === $item[0] ) {
									    /* Nemá smysl zjišťovat všechny skupiny. Stačí zjistit, jestli do ní patří aktuální uživatel a přidat ho
									    */
										if ( $item[1] ) {
											$allow[EDIT][ $wgUser->mName ] = true;
										} else {
											$allow[VIEW][ $wgUser->mName ] = true;
										}
									}
								}
							}
						}
						/* MW skupina nemusí být použita, zkoumá se jméno */
						if ( $item[0] === $wgUser->mName ) {
							/* Username */
							if ( $item[1] ) {
								$allow[EDIT][ $wgUser->mName ] = true;
							} else {
								$allow[VIEW][ $wgUser->mName ] = true;
							}
						}
						if ( $item[1] ) {
							$allow[EDIT][ $item[0] ] = true;
						} else {
							$allow[VIEW][ $item[0] ] = true;
						}
					} else {
						if ( array_key_exists( EDIT, $array ) ) {
							if ( $item[1] ) {
								foreach( array_keys( $array[EDIT] ) as $user ) {
									$allow[EDIT][ $user ] = true;
								}
							} else {
								/* (ro) */
								foreach( array_keys( $array[EDIT] ) as $user ) {
									$allow[EDIT][ $user ] = false;
									$allow[VIEW][ $user ] = true;
								}
							}
						}
						if ( array_key_exists( VIEW, $array ) ) {
							foreach( array_keys( $array[VIEW] ) as $user ) {
								$allow[VIEW][ $user ] = true;
							}
						}
					}
				}
//				self::printDebug( $allow ); // INFO DEBUG
			}
		}
//		self::printDebug( $allow ); // INFO DEBUG
		return $allow;
	}


	/**
	 * Function parse input string, if is only title, without namespace, or
	 *  full title of page as 'User:Anybody' or 'Private:Grouplist' & etc.
	 *
	 * @param string $title
	 * @param int|null $namespaceID
	 *
	 * @return array $target By default array as [ 'title', 0 ]
	 */
	private static function getAccessListCanonicalTarget(
		$string,
		$namespaceID = 0
		) {
		global $wgContLang;
		$target = [];
		preg_match(
			'/(.*?):/',
			$string,
			$match,
			PREG_UNMATCHED_AS_NULL
			);
		if ($match) {
			$index = MWNamespace::getCanonicalIndex( strtolower( $match[1] ) );
			if ( $index === null ) {
				// If is name of namespace invalid, or in localize form, is value of $index null
				$pos = strpos( $string, ':' );
				if ( $pos === false ) {
					// only string, without colon
					$target['title'] = trim( $string );
					$target['ns'] = $namespaceID;
				} else {
					// Name of namespace in localize form by current settings of MediaWiki, i.e. 'Uživatel'
					$stringfortest = str_replace( " ", "_", substr( $string, 0, $pos ) );
					foreach( MWNamespace::getValidNamespaces() as $index ) {
						if ( $wgContLang->getNsText( $index ) === $stringfortest ) {
							$target['title'] = trim( str_replace( "$stringfortest:", '', $string ) );
							$target['ns'] = $index;
							break;
						}
					}
					// If is not valid name of namespace, is $string name of page in main namespaces with ID 0
					if ( array_key_exists( 'title', $target ) === false ) {
						$target['title'] = trim( $string );
						$target['ns'] = 0;
					}
				}
			} else {
				// Canonical name of namespace return integer, i.e. for 'User' is 2
				$target['title'] = trim( substr( $string, strpos( $string, ':' ) + 1 ) );
				$target['ns'] = $index;
			}
		} else {
			// $string without colon, is it name of page from main namespace
			$target['title'] = trim( $string );
			$target['ns'] = $namespaceID;
		}
		return $target;
	}


	/**
	 * Function get raw content of page, which is identified by name and namespace.
	 *
	 * @param int $ns Namespace ID
	 * @param string $title Name of page
	 *
	 * @return string $content
	 */
	private static function getContentPage(
		$ns,
		$title
		) {
		global $wgVerifyPage;
		if ( is_integer( strpos( $title, '{' ) ) ) {
			// remove templates
			return '';
		}
		if ( is_integer( strpos( $title, '#' ) ) ) {
			// remove functions
			return '';
		}
		// remove magic keys
		//TODO
//		$start = microtime(true); // START DEBUG TIMESTAMP
		$gt = Title::makeTitle( $ns, $title );
		if ( $gt->isSpecialPage() ) {
			// Can't create WikiPage for special page
			return '';
		}
		$page = WikiPage::factory( $gt );
		$latestid = $page->getLatest();
		$content = ContentHandler::getContentText( $page->getContent() );
		if ( is_array($wgVerifyPage) ) {
			if ( ! array_key_exists( $latestid, $wgVerifyPage ) ) {
				$wgVerifyPage[ $latestid ] = true;
			}
		}
//		self::printDebug( $start . ' getContentPage' . ' title="' . $title . '" ns="' . $namespace . '" + ' . ( microtime(true) - $start ) ); //END DEBUG TIMESTAMP
		return $content;
	}


	/**
	 * Function get rights array for page, which is identified by name and namespace.
	 *
	 * @param string $title
	 * @param int $ns
	 *
	 * @return array $array
	 */
	private static function getContentPageNew(
		$title,
		$ns
		) {
		/* Return array with two keys: visitors and editors */
		$content = self::getContentPage( $ns, $title );
		if ( strpos( $content, '* ' ) === 0 ) {
			$array = self::parseOldList( $content );
		} else {
			$array = self::parseNewList( $content );
		}
		return $array;
	}


	/**
	 * Function test if current user is logged or not.
	 *
	 * @param User $user
	 *
	 * @return bool|null
	 */
	private static function isUser( $user ) {
		$title = Title::newFromText( $user, NS_USER );
		if ( $title !== null ) {
			return true;
		}
	}


	/**
	 *
	 * @param string $string
	 *
	 * @return array $output
	 */
	private static function membersOfGroup( $string ) {
		$output = [];
		$array = explode( '=', $string );
//		self::printDebug( $array ); // INFO DEBUG
		if ( count( $array ) > 1 ) {
			if ( strpos( $array[1], '}' ) ) {
				$members = trim( substr( $array[1], 0, strpos( $array[1], '}' ) ) );
			} else {
				$members = trim( $array[1] );
			}
			$name = trim( $array[0] );
			$output[$name] = [];
			if ( strpos( $members, '(ro)' ) ) {
				// invalid syntax!
				return false;
			} else {
				foreach ( explode( ',', $members ) as $item ) {
					array_push( $output[ $name ], trim( $item ) );
				}
			}
		}
		return $output;
	}


	/**
	 *
	 * @param string $string
	 *
	 * @return array
	 */
	private static function oldSyntaxTest( $string ) {
		/* Blok kvůli staré syntaxi. uživatel, nebo členové
		    skupiny budou mít automaticky pouze readonly
		    přístup, pokud je přítomen za jménem, či jménem
		    skupiny řetězec '(ro)'. A to bez ohledu na
		    práva v accesslistu. */
//		self::printDebug( $retezec ); // INFO DEBUG
		$ro = strpos( $string, '(ro)' );
		if ( $ro ) {
			// Blok kvůli staré syntaxi. Skupina, nebo uživatel bude mít automaticky pouze readonly přístup, bez ohledu na volbu accesslistu.
			return [ trim( str_replace( '(ro)', '', $string ) ) ,  false ];
		} else {
			return [ trim( $string ), true ];
		}
	}


	/**
	 * Function parse explode string by pipe char and test to AccessControl params
	 *
	 * @param string $string
	 *
	 * @return array $allow
	 */
	private static function parseNewList( $string ) {
		$allow = [];
		$usersAccess = array_map( 'trim', explode( '|' , $string ) );
		if ( is_array($usersAccess) ) {
			foreach ( $usersAccess as $userEntry ) {
				$item = trim($userEntry);
				if ( substr( $userEntry, 0, 21) === READGROUPS ) {
					$visitorsGroup = self::membersOfGroup( $item );
					self::appendMembers( $allow, $visitorsGroup, READGROUPS, false );
				}
				if ( substr( $userEntry, 0, 17) === EDITGROUPS ) {
					$editorsGroup = self::membersOfGroup( $item );
					self::appendMembers( $allow, $editorsGroup, EDITGROUPS );
				}
				if ( substr( $userEntry, 0, 20) === READERS ) {
					$visitors = self::membersOfGroup( $item );
					self::appendUsers( $allow, $visitors, READERS, VIEW );
				}
				if ( substr( $userEntry, 0, 16) === EDITORS ) {
					$editors = self::membersOfGroup( $item );
					self::appendUsers( $allow, $editors, EDITORS, EDIT );
				}
			}
		}
		return $allow;
	}


	/**
	 * Function add into rights array the members of groups
	 *
	 * @param array &$allow 
	 * @param array $array
	 * @param string $param
	 * @param bool $edit
	 */
	private static function appendMembers( &$allow, $array, $param, $edit = true ) {
		global $wgRequest;
		$title = $wgRequest->getText('title');
		if ( ! empty ( $array ) ) {
			foreach ( $array[$param] as $group ) {
				if ( $group != $title ) {
					$members = self::testRightsOfMember( $group );
					if ( array_key_exists( EDIT, $members ) ) {
						foreach( array_keys( $members[EDIT] ) as $item ) {
							if ( strlen( $item ) > 1 ) {
								$allow[EDIT][$item] = $edit;
							}
						}
					}
					if ( array_key_exists( VIEW, $members ) ) {
						foreach( array_keys($members[VIEW]) as $item ) {
							if ( strlen( $item ) > 1 ) {
								$allow[EDIT][$item] = true;
							}
						}
					}
				}
			}
		}
	}


	/**
	 * Function add the users into rights array
	 *
	 * @param array &$allow 
	 * @param array $array
	 * @param string $param
	 * @param string $group visitors pr editors
	 * @param bool $edit
	 */
	private static function appendUsers( &$allow, $array, $param, $group, $bool = true ) {
		if ( ! empty ( $array ) ) {
			foreach ( $array[$param] as $item ) {
				if ( strlen( $item ) > 1 ) {
					$allow[$group][$item] = $bool;
				}
			}
		}
	}


	/**
	 * Function parse content by old syntax for AccessControl lists
	 *
	 * @param string $string
	 *
	 * @return array $allow
	 */
	private static function parseOldList( $string ) {
		/* Extracts the users from the userspace access list by the old syntax */
		$allow = [];
		$usersAccess = explode( "\n", $string );
		foreach ( $usersAccess as $userEntry ) {
			if ( substr( $userEntry, 0, 1 ) == "*" ) {
				if ( strpos( $userEntry, "(ro)" ) === false ) {
					$user = trim( str_replace( "*", "", $userEntry ) );
					if ( self::isUser($user) ) {
						$allow[EDIT][$user] = true;
					}
				} else {
					$user = trim( str_replace( "(ro)", "", str_replace( "*", "", $userEntry ) ) );
					if ( self::isUser($user) ) {
						$allow[VIEW][$user] = true;
					}
				}
			}
		}
		return $allow;
	}


	/**
	 * Function print info about protection by AccessControl to header of the page
	 */
	private static function printAccessControlInfo() {
		global $wgAccessControlInfo, $wgOut;
		$style = "<p id=\"accesscontrol\" style=\"text-align:center;color:#BA0000;font-size:8pt\">";
		$text = wfMessage( 'accesscontrol-info' )->text();
		$style_end = "</p>";
		$wgAllowInfo = $style . $text . $style_end;
		if ( empty( $wgAccessControlInfo ) ) {
			return $wgAllowInfo;
		} else {
//			self::printDebug( microtime(true) . ' ' . $wgAccessControlInfo . ' printAccessControlInfo' ); // DEBUG TIMESTAMP
			$wgOut->addHTML($wgAllowInfo);
		}
	}


	/**
	 * Function for print debug message into HTML code of the page
	 *  Its only for debug and tests! For normal using is recommend
	 *  comment all lines where is string DEBUG
	 *
	 * @param string|array|object $input
	 */
	private static function printDebug(
		$input
	) {
		print_r('<!-- ');
		print_r($input);
		print_r(' -->
');
	}


	/**
	 * Limits of user rights to the page, which is
	 *  for current user only to read.
	 */
	private static function readOnlyUser() {
		global $wgActions, $wgUser, $wgReadOnlyUser, $wgOut;
		if ( ! $wgReadOnlyUser ) {
			$wgActions['edit'] = false;
			$wgActions['history'] = false;
			$wgActions['submit'] = false;
			$wgActions['info'] = false;
			$wgActions['raw'] = false;
			$wgActions['delete'] = false;
			$wgActions['revert'] = false;
			$wgActions['revisiondelete'] = false;
			$wgActions['rollback'] = false;
			$wgActions['markpatrolled'] = false;
			$wgActions['formedit'] = false;
//			self::printDebug( microtime(true) . ' readOnlyUser variable $wgReadOnlyUser is set true' ); // DEBUG TIMESTAMP
			$wgOut->addInlineScript( "document.getElementById('ca-history') && document.getElementById('ca-history').parentNode.removeChild(document.getElementById('ca-history'));" );
			$wgOut->addInlineScript( "document.getElementById('ca-edit') && document.getElementById('ca-edit').parentNode.removeChild(document.getElementById('ca-edit'));" );
			$wgOut->addInlineScript( "document.getElementById('ca-ve-edit') && document.getElementById('ca-ve-edit').parentNode.removeChild(document.getElementById('ca-ve-edit'));" );
			$wgOut->addInlineScript( "Array.from(document.getElementsByClassName('mw-editsection')).map(element => element.parentNode.removeChild(element));" );
			$wgReadOnlyUser = true;
		}
		return;
	}


	/**
	 * Function test if current user name is in array of rights
	 *
	 * @param array $rights
	 *
	 * @return int|bool
	 */
	private static function testRightsArray ( $rights ) {
		global $wgUser, $wgAdminCanReadAll;
		if ( empty( $rights[VIEW] ) && empty( $rights[EDIT] ) ) {
			/* stránka je bez ochrany */
			return 1;
		}
		if ( in_array( 'sysop', $wgUser->getGroups(), true ) ) {
			if ( isset( $wgAdminCanReadAll ) ) {
				if ( $wgAdminCanReadAll ) {
					/* admin může vše */
					return 1;
				}
			}
		}
		if ( array_key_exists( $wgUser->mName, $rights[EDIT] ) || array_key_exists( $wgUser->mName, $rights[VIEW] ) ) {
			if ( array_key_exists( $wgUser->mName, $rights[EDIT] ) && $rights[EDIT][$wgUser->mName] ) {
				return 1;
			} else {
				/* uživatel může číst obsah */
				return 2;
			}
		} else {
			return false;
		}
	}


	/**
	 *
	 * @param string $string
	 *
	 * @return array $allow
	 */
	private static function testRightsOfMember( $string ) {
		/* Na vstupu je řetězec se jménem uživatele, nebo uživatelské skupiny
		    na výstupu je pole s aktuálním nastavením práv
		    [ userA = false, userB = 'read', userC = 'edit']
		*/
//		$allow = [];
		$item = self::oldSyntaxTest( $string );
//		self::printDebug( $item ); // INFO DEBUG
		if ( is_array( $item ) ) {
			$accesslistpage = self::getAccessListCanonicalTarget( $item[0] );
			if ( $accesslistpage[ 'ns' ] === 2 ) {
				//netřeba dál chodit, je to user
				if ( $item[1] ) {
					$allow[EDIT][ $accesslistpage['title'] ] = true;
				} else {
					$allow[VIEW][ $accesslistpage['title'] ] = true;
				}
			} else {
				/* extrakce obsahu seznamu (předává se jmenný prostor a jméno seznamu) */
				$allow = self::getContentPageNew( $accesslistpage['title'], $accesslistpage['ns'] );
			}
		}
//		self::printDebug( $allow ); // INFO DEBUG
		return $allow;
	}


	/**
	 * Function verify array with rights for logged user and call function
	 *  printAccessControlInfo(), what print info about protection to page
	 *  if exists array with rights.
	 *
	 * @param array $rights
	 *
	 * @return bool
	*/
	private static function userVerify( $rights ) {
		global $wgUser, $wgActions, $wgAdminCanReadAll, $wgAccessControlInfo, $wgRequest;
		if ( empty( $rights[VIEW] ) && empty( $rights[EDIT] ) ) {
			/* page is without limits */
			return true;
		} else {
			if (! $wgAccessControlInfo ) {
				$wgAccessControlInfo = 'Protected by AccessControl';
				self::printAccessControlInfo();
			}
			if ( $wgUser->mId === 0 ) {
				/* Redirection unknown users */
//				self::printDebug( microtime(true) . ' userVerify - anonymous' ); // DEBUG TIMESTAMP
				$wgActions['view'] = false;
//				self::doRedirect( 'accesscontrol-anonymous' );
			} else {
				if ( in_array( 'sysop', $wgUser->getGroups(), true ) ) {
//					self::printDebug( microtime(true) . ' userVerify - ' . $wgUser->mName . ' is sysop' ); // DEBUG TIMESTAMP
					if ( isset( $wgAdminCanReadAll ) ) {
						if ( $wgAdminCanReadAll ) {
							return true;
						}
					}
				}
			}
			if ( array_key_exists( EDIT, $rights ) ) {
				if ( array_key_exists( $wgUser->mName, $rights[EDIT] ) ) {
					if ( $rights[EDIT][$wgUser->mName] ) {
//						self::printDebug( microtime(true) . ' userVerify - ' . $wgUser->mName . ' is  editor' ); // DEBUG TIMESTAMP
						return true;
					}
				}
			}
			if ( array_key_exists( VIEW, $rights ) ) {
				self::readOnlyUser();
				if ( array_key_exists( $wgUser->mName, $rights[EDIT] ) || array_key_exists( $wgUser->mName, $rights[VIEW] ) ) {
					if ( $rights[VIEW][$wgUser->mName] ) {
						if (  $wgRequest->getText( 'veaction' ) ) {
//							self::printDebug( microtime(true) . ' userVerify - ' . $wgUser->mName . ' is visitor by visual editor' ); // DEBUG TIMESTAMP
							return self::doRedirect( 'accesscontrol-redirect-users' );
						} else {
//							self::printDebug( microtime(true) . ' userVerify - ' . $wgUser->mName . ' is visitor' ); // DEBUG TIMESTAMP
							return true;
						}
					} else {
//						self::printDebug( microtime(true) . ' userVerify - unauthorized user ' . $wgUser->mName ); // DEBUG TIMESTAMP
						$wgActions['view'] = false;
						return self::doRedirect( 'accesscontrol-redirect-users' );
					}
				} else {
//					self::printDebug( microtime(true) . ' userVerify - user ' . $wgUser->mName . ' is not member of accesslist' ); // DEBUG TIMESTAMP
					$wgActions['view'] = false;
					if ( empty( $wgRequest->getText( 'search' ) ) ) {
						return self::doRedirect( 'accesscontrol-redirect-users' );
					}
				}
			}
		}
	}

}
