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
    private $external_id = null;

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

            // first find the session ID that was passed back by Laravel :
            $authManager = AuthManager::singleton();
            $request = $authManager->getRequest();
            $sid = $request->getText('request_sid');

            // Dev note : at this point, we could save $sid in the session (setSessionVariable), so that 
            //            we can disconnect the userfrom Laravel in deauthenticate()

            if (empty($key) || empty($sid))
            {
                $errorMessage = wfMessage('neayiauth-authentication-failure')->plain();
                return false;                
            }

            $api_url = 'https://questions.dev.tripleperformance.fr/api.php?' . http_build_query(array('token' => $key, 'sid' => $sid));

            // - dev only - With our self signed certificate, lets allow weaker certificates:
            $arrContextOptions = array();
            if (strpos($api_url, '.dev.') !== false)
            {
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

            // make sure the UserName starts with an upercase : https://www.mediawiki.org/wiki/Topic:R97c76vpuokaqby9
            $user_info['name'] = mb_convert_case($user_info['name'], MB_CASE_TITLE, 'UTF-8');
            if (!isset($user_info['name']) || !User::isValidUserName($user_info['name'])) {
                $errorMessage = wfMessage('neayiauth-invalid-username')->plain();
                return false;
            }

            $username = $user_info['name'];

            $realname = isset($user_info['realname']) ? $user_info['realname'] : '';
            $email = isset($user_info['email']) ? $user_info['email'] : '';
            $this->external_id = $user_info['id']; // Required too.

            $local_user_id = $this->getMediawikiUserIdForExternalId();
            $user = null;
            $id = null;

            if (!empty($local_user_id))
            {
                $user = User::newFromId($local_user_id);
                if (!empty($user))
                {
                    // NB: there's no need to update the realname or email - this is taken care
                    // by pluggable auth. See that $wgPluggableAuth_EnableLocalProperties is left at the default value (false)
                    
                    // It is not possible to simply change the UserName. 
                    // See https://www.mediawiki.org/wiki/Extension:Renameuser to understand the
                    // steps required for changing the username. In the time being we just make sure the 
                    // $username is as stored in DB
                    $username = $user->getName();
                }
            }

            if (empty($user))
            {
                // Create the user or log in using the UserName
                $user = User::newFromName($username);
            }

            if (!empty($user))
                $id = $user->getId() === 0 ? null : $user->getId();
            
            if (!empty($id) && empty($local_user_id)) {
                // Store $this->external_id
                $this->saveExtraAttributes($id);
            }

            return true;
        }


        // Step 1 - Start the login process

        // Redirect to laravel with some token that we keep safe in our session:
        $token = uniqid();
        $this->setSessionVariable('request_key', $token);
        $this->saveSession();

        $auth_url = 'https://questions.dev.tripleperformance.fr/login.php?'
                    . http_build_query(array('redirectUri' => $GLOBALS['wgOAuthRedirectUri'],
                                             'token' => $token));
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

        // Dev note : it would be nice if we could unlog from laravel too, but we're 
        //            in an API and we lost the laravel session ID. Not a problem. See dev note above.
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
        $dbr = wfGetDB(DB_MASTER);
        $dbr->insert('neayiauth_users', ['neayiauth_user' => $id,
                                         'neayiauth_external_userid' => $this->external_id]);
    }

    /**
     * Returns the mediawiki user id for the given external ID from laravel.
     *
     * @return int the local user id
     */
    private function getMediawikiUserIdForExternalId()
    {
        if (empty($this->external_id)) 
            return false;

        $dbr = wfGetDB(DB_REPLICA);
		$result = $dbr->selectRow(
			'neayiauth_users',
			[
				'neayiauth_user'
			],
			[
				'neayiauth_external_userid' => $this->external_id
			],
			__METHOD__
		);
		if ( $result ) 
            return (int)$result->neayiauth_user;
            
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
        $directory = $GLOBALS['wgExtensionDirectory'] . '/NeayiAuth/sql';
        $type = $updater->getDB()->getType();
        $sql_file = sprintf("%s/%s/table_neayiauth_users.sql", $directory, $type);

        if (!file_exists($sql_file)) {
            throw new MWException("NeayiAuth does not support database type `$type`.");
        }

        $updater->addExtensionTable('neayiauth_users', $sql_file);
    }
}