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

use \MediaWiki\Auth\AuthManager;


/**
 * Class NeayiAuth
 */
class NeayiAuth extends AuthProviderFramework
{
    /**
     * NeayiAuth constructor.
     * @internal
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Inherited from PluggableAuth
     * @see https://www.mediawiki.org/wiki/Extension:PluggableAuth for description of the call
     * 
     * @param $id
     * @param $username
     * @param $realname
     * @param $email
     * @param $errorMessage
     * @return bool
     * @throws FatalError
     * @throws MWException
     * @internal
     */
    public function authenticate(&$id, &$username, &$realname, &$email, &$errorMessage)
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

            $hook = Hooks::run('NeayiAuthAfterGetUser', [&$user_info, &$errorMessage]);

            // Request failed or user is not authorised.
            if (empty($user_info) || $hook === false) {
                $errorMessage = !empty($errorMessage) ? $errorMessage : wfMessage('neayiauth-authentication-failure')->plain();
                return false;
            }

            if (!empty($user_info['error'])) {
                $errorMessage = wfMessage('neayiauth-authentication-failure')->plain() . ' ' . print_r($user_info, true);
                return false;
            }

            // make sure the UserName starts with an upercase : https://www.mediawiki.org/wiki/Topic:R97c76vpuokaqby9
            $username = mb_convert_case($user_info['name'], MB_CASE_TITLE, 'UTF-8');
            
            // Suffix with the CRC of the GUID, but only up to 235 chars max
            $crc = ' (' . crc32($user_info['id']) . ')';
            $maxlength = 235;
            $username = mb_substr($username, 0, $maxlength - strlen($crc)) . $crc;
           
            if (!User::isValidUserName($username)) {
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

            if (!empty($id)) {
                $user = User::newFromId($id);
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
                $user = User::newFromName($username);
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
        $token = uniqid();
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
     * @param User $user
     * @return void
     * @throws FatalError
     * @throws MWException
     * @internal
     */
    public function deauthenticate(User &$user)
    {
        Hooks::run('NeayiAuthBeforeLogout', [&$user]);

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
     * @param $id
     * @return void
     * @throws DBError
     * @internal
     */
    public function saveExtraAttributes($id)
    {
        $guid = $this->getSessionVariable("AuthManager::neayiAuthGuid");
        $api_token = $this->getSessionVariable("AuthManager::neayiAuthAPIToken");

        if ($guid === null){
            return;
        }

        $dbr = wfGetDB(DB_MASTER);
        $dbr->query( "INSERT INTO ".$dbr->tableName('neayiauth_users')." (neayiauth_user, neayiauth_external_userid, neayiauth_external_apitoken) 
                        VALUES (" .$dbr->addQuotes($id). ", " .$dbr->addQuotes($guid). ", " .$dbr->addQuotes($api_token). ")
                        ON DUPLICATE KEY UPDATE neayiauth_external_userid = " .$dbr->addQuotes($guid). ",
                                                neayiauth_external_apitoken = " .$dbr->addQuotes($api_token),
            __METHOD__
            );
    }

    /**
     * Returns the mediawiki user id for the given external ID from laravel.
     *
     * @return int the local user id
     */
    private function getMediawikiUserIdForExternalId($guid)
    {
        if (!empty($guid))
        {
            $dbr = wfGetDB(DB_REPLICA);
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
     * @return int the local user id
     */
    private function getMediawikiUserIdForEmail($email)
    {
        if (!empty($email))
        {
            $dbr = wfGetDB(DB_REPLICA);
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
     * @throws MWException
     * @internal
     */
    public static function onPluggableAuthPopulateGroups(User $user)
    {
        $result = Hooks::run('NeayiAuthBeforeAutoPopulateGroups', [&$user]);

        if ($result === false) {
            return false;
        }

        if (!isset($GLOBALS['wgOAuthAutoPopulateGroups'])) {
            return false;
        }

        // Subtract the groups the user already has from the list of groups to populate.
        $populate_groups = array_diff((array)$GLOBALS['wgOAuthAutoPopulateGroups'], $user->getEffectiveGroups());

        foreach ($populate_groups as $populate_group) {
            $user->addGroup($populate_group);
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
     * @internal
     */
    public static function onLoadExtensionSchemaUpdates(DatabaseUpdater $updater)
    {
        $type = $updater->getDB()->getType();
        $dir = $GLOBALS['wgExtensionDirectory'] . DIRECTORY_SEPARATOR .
			'NeayiAuth' . DIRECTORY_SEPARATOR . 'sql' . DIRECTORY_SEPARATOR . $type . DIRECTORY_SEPARATOR;

        $sql_file = $dir . 'table_neayiauth_users.sql';

        if (!file_exists($sql_file)) {
            throw new MWException("NeayiAuth does not support database type `$type`.");
        }
        
        $updater->addExtensionTable('neayiauth_users', $sql_file);
        $updater->addExtensionField( 'neayiauth_users', 'neayiauth_external_apitoken',
            $dir  . 'field_neayiauth_external_apitoken.sql' );
    }
}
