<?php
/**
 * Copyright 2020 Bertrand Gorge
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


namespace Neayi\Extension\NeayiAuth;

use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\User\UserIdentity;
use MediaWiki\MediaWikiServices;
use Wikimedia\Rdbms\IConnectionProvider;
use MediaWiki\User\User;
use MediaWiki\Installer\DatabaseUpdater;
use RuntimeException;
use FatalError;

/**
 * Class NeayiAuth
 */
class NeayiAuth extends PluggableAuth
{
    private $session;

    /** @var IConnectionProvider */
    private $dbProvider;

    public function __construct()
    {
        $session_manager = \MediaWiki\Session\SessionManager::singleton();
        $this->session = $session_manager->getGlobalSession();
        $this->dbProvider = MediaWikiServices::getInstance()->getConnectionProvider();
    }

    /**
     * Exposes the set() method from MediaWiki\Session\Session.
     *
     * @param $key
     * @param $value
     */
    private function setSessionVariable($key, $value)
    {
        $this->session->set($key, $value);
    }

    /**
     * Exposes the remove() method from MediaWiki\Session\Session.
     *
     * @param $key
     */
    private function removeSessionVariable($key)
    {
        $this->session->remove($key);
    }

    /**
     * Exposes the get() method from MediaWiki\Session\Session.
     *
     * @param $key
     * @return null|string
     */
    private function getSessionVariable($key)
    {
        return $this->session->get($key);
    }

    /**
     * Exposes the exists() method from MediaWiki\Session\Session.
     *
     * @param $key
     * @return bool
     */
    private function doesSessionVariableExist($key)
    {
        return $this->session->exists($key);
    }

    /**
     * Exposes the save() method from MediaWiki\Session\Session.
     */
    private function saveSession()
    {
        $this->session->save();
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     *
	 * @param int|null &$id The user's user ID
	 * @param string|null &$username The user's username
	 * @param string|null &$realname The user's real name
	 * @param string|null &$email The user's email address
	 * @param string|null &$errorMessage Returns a descriptive message if there's an error
	 * @return bool true if the user has been authenticated and false otherwise
	 * @since 1.0
	 *
	 */
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage ): bool
    {
        if ($this->doesSessionVariableExist("request_key")) {

            // Step 2 - Use the API to get the user's detail from Laravel

            $key = $this->getSessionVariable("request_key");
            $this->removeSessionVariable("request_key");
            $this->removeSessionVariable("AuthManager::neayiAuthGuid");
            $this->removeSessionVariable("AuthManager::neayiAuthAPIToken");

            if (empty($key)) {
                $errorMessage = wfMessage('neayiauth-authentication-failure')->plain();
                return false;
            }
            $wgOAuthUserApiByToken = $GLOBALS['wgOAuthUserApiByToken'];
            $api_url = $wgOAuthUserApiByToken. http_build_query(['wiki_token' => $key]);

            // - dev only - With our self signed certificate, lets allow weaker certificates:
            $arrContextOptions = [];
            if (strpos($api_url, '.dev.') !== false) {
                $arrContextOptions = array(
                    "ssl" => array(
                        "allow_self_signed" => true,
                        "verify_peer" => false,
                        "verify_peer_name" => false,
                    ),
                );
            }
            // - end dev only -

            $response = file_get_contents($api_url, false, stream_context_create($arrContextOptions));

            $user_info = json_decode($response, true);

            // Request failed or user is not authorised.
            if (empty($user_info) || !is_array($user_info)) {
                $errorMessage = !empty($errorMessage) ? $errorMessage : wfMessage('neayiauth-authentication-failure')->plain();
                return false;
            }

            if (!empty($user_info['error'])) {
                $errorMessage = wfMessage('neayiauth-authentication-failure')->plain() . ' ' . print_r($user_info, true);
                return false;
            }

            // Validate required fields
            if (empty($user_info['name']) || empty($user_info['id'])) {
                $errorMessage = wfMessage('neayiauth-authentication-failure')->plain() . ' Missing required user data.';
                return false;
            }

            // make sure the UserName starts with an upercase : https://www.mediawiki.org/wiki/Topic:R97c76vpuokaqby9
            $username = mb_convert_case($user_info['name'], MB_CASE_TITLE, 'UTF-8');

            // Suffix with the CRC of the GUID, but only up to 235 chars max
            $crc = ' (' . crc32($user_info['id']) . ')';
            $maxlength = 235;
            $username = mb_substr($username, 0, $maxlength - strlen($crc)) . $crc;

            $userNameUtils = MediaWikiServices::getInstance()->getUserNameUtils();
            if ( !$userNameUtils->isValid( $username ) ) {
                $errorMessage = wfMessage('neayiauth-invalid-username')->plain();
                return false;
            }

            $realname = isset($user_info['realname']) ? $user_info['realname'] : '';
            $email = isset($user_info['email']) ? $user_info['email'] : '';
            $guid = $user_info['id']; // Required too.

            $id = $this->getMediawikiUserIdForExternalId($guid);
            if (empty($id))
                $id = $this->getMediawikiUserIdForEmail($email);

            $user = null;
            $userFactory = MediaWikiServices::getInstance()->getUserFactory();

            if (!empty($id)) {
                $user = $userFactory->newFromId( $id );
                if (!empty($user)) {
                    // NB: there's no need to update the realname or email - this is taken care
                    // by pluggable auth. See that $wgPluggableAuth_EnableLocalProperties is left at the default value (false)

                    // It is not possible to simply change the UserName.
                    // See https://www.mediawiki.org/wiki/Extension:Renameuser to understand the
                    // steps required for changing the username. In the time being we just make sure the
                    // $username is as stored in DB
                    $username = $user->getName();
                }
            }

            if (empty($user)) {
                // Create the user or log in using the UserName
                $user = $userFactory->newFromName( $username );
            }

            if (!empty($user)) {
                $id = $user->getId() === 0 ? null : $user->getId();
            }

            if (!empty($guid))
                $this->setSessionVariable( 'AuthManager::neayiAuthGuid', $guid );

            if (!empty($user_info['token']))
                $this->setSessionVariable( 'AuthManager::neayiAuthAPIToken', $user_info['token'] );

            if (!empty($id))
                $this->saveExtraAttributes($id);

            return true;
        }


        // Step 1 - Start the login process

        // Redirect to laravel with some token that we keep safe in our session:
        $token = substr(bin2hex(random_bytes(32)), 0, 13);
        $this->setSessionVariable('request_key', $token);
        $this->saveSession();

        $data = [
            'wiki_callback' => $GLOBALS['wgOAuthRedirectUri'],
            'wiki_token' => $token
        ];
        $auth_url = $GLOBALS['wgOAuthUri']. http_build_query($data);
        header("Location: $auth_url");
        exit;
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     *
	 * @param UserIdentity &$user
	 * @since 1.0
	 */
	public function deauthenticate( UserIdentity &$user ): void
    {
        $this->removeSessionVariable("request_key");

        // $guid = $this->getSessionVariable("AuthManager::neayiAuthGuid");

        // Todo: it would be nice if we could unlog from laravel too.
        // For the moment the only way to logout is to go to https://insights.dev.tripleperformance.fr/user/logout
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     *
     * Store the laravel ID in neayiauth_users so that we can match when necessary
     *
     * @param int $id user id
	 * @since 1.0
	 */
	public function saveExtraAttributes( int $id ): void
    {
        $guid = $this->getSessionVariable("AuthManager::neayiAuthGuid");
        $api_token = $this->getSessionVariable("AuthManager::neayiAuthAPIToken");

        if ($guid === null){
            return;
        }

		$dbw = $this->dbProvider->getPrimaryDatabase();
        $dbw->upsert(
            'neayiauth_users',
            [
                'neayiauth_user' => $id,
                'neayiauth_external_userid' => $guid,
                'neayiauth_external_apitoken' => $api_token
            ],
            [ 'neayiauth_user' ],
            [
                'neayiauth_external_userid' => $guid,
                'neayiauth_external_apitoken' => $api_token
            ],
            __METHOD__
        );
    }

    /**
     * Returns the mediawiki user id for the given external ID from laravel.
     *
     * @param string $guid The external user ID
     * @return int|false The local user id or false if not found
     */
    private function getMediawikiUserIdForExternalId($guid)
    {
        if (!empty($guid))
        {
            $dbr = $this->dbProvider->getReplicaDatabase();

            $result = $dbr->selectRow(
                'neayiauth_users',
                [
                    'neayiauth_user'
                ],
                [
                    'neayiauth_external_userid' => $guid
                ],
                __METHOD__
            );
            if ( $result )
                return (int)$result->neayiauth_user;
        }

        return false;
    }

    /**
     * Returns the mediawiki user id for the given email from laravel.
     *
     * @param string $email The user's email address
     * @return int|false The local user id or false if not found
     */
    private function getMediawikiUserIdForEmail($email)
    {
        if (!empty($email))
        {
            $dbr = $this->dbProvider->getReplicaDatabase();
            $result = $dbr->selectRow(
                'user',
                [
                    'user_id'
                ],
                [
                    'user_email' => $email
                ],
                __METHOD__
            );
            if ( $result )
                return (int)$result->user_id;
        }

        return false;
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     *
     * Adds the user to the groups after authentication.
     *
     * @param User $user
     * @return bool
     * @throws FatalError
     * @internal
     */
    public static function onPluggableAuthPopulateGroups(User $user)
    {
        if (!isset($GLOBALS['wgOAuthAutoPopulateGroups'])) {
            return false;
        }

        // Subtract the groups the user already has from the list of groups to populate.
        $userGroupManager = MediaWikiServices::getInstance()->getUserGroupManager();
        $groups = $userGroupManager->getUserEffectiveGroups( $user );
        $populate_groups = array_diff((array)$GLOBALS['wgOAuthAutoPopulateGroups'], $groups);

        foreach ($populate_groups as $populate_group) {
            $userGroupManager->addUserToGroup( $user, $populate_group );
        }

        return true;
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     *
     * Fired when MediaWiki is updated to allow NeayiAuth to register updates for the database schema.
     *
     * @param DatabaseUpdater $updater
     * @throws RuntimeException If the database type is not supported
     * @internal
     */
    public static function onLoadExtensionSchemaUpdates(DatabaseUpdater $updater)
    {
        $type = $updater->getDB()->getType();
        $dir = $GLOBALS['wgExtensionDirectory'] . DIRECTORY_SEPARATOR .
			'NeayiAuth' . DIRECTORY_SEPARATOR . 'sql' . DIRECTORY_SEPARATOR . $type . DIRECTORY_SEPARATOR;

        $sql_file = $dir . 'table_neayiauth_users.sql';

        if (!file_exists($sql_file)) {
            throw new RuntimeException("NeayiAuth does not support database type `$type`.");
        }

        $updater->addExtensionTable( 'neayiauth_users', $sql_file);
        $updater->addExtensionField( 'neayiauth_users', 'neayiauth_external_apitoken',
            $dir  . 'field_neayiauth_external_apitoken.sql' );
    }
}
