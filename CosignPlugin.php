<?php
/**
 * CosignPlugin for phplist
 *
 * This file is a part of CosignPlugin.
 *
 * This plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * @category    phplist
 * @package     CosignPlugin
 * @license     http://www.gnu.org/licenses/gpl.html GNU General Public License, Version 3
 */

 /**
 * Registers the plugin with phplist
 */
class CosignPlugin extends phplistPlugin
{
    /*
    * Inherited Variables
    */
    public $name = 'Cosign Plugin';
    public $description = 'Use Cosign SSO to authenticate administrators';
    public $enabled = 1;
    public $version = '1.0';

    // these 2 settings create fields on lists/admin/?page=configure under the cosign section
    public $settings = array(
        'cosign_realm' => array(
            'description' => 'Cosign required realm (leave empty to not validate)',
            'type' => 'text',
            'value' => '',
            'allowempty' => true,
            'category'=> 'Cosign',
        ),
        'cosign_logout' => array(
            'description' => 'the url where your cosign service is hosted',
            'type' => 'text',
            'value' => '',
            'allowempty' => true,
            'category'=> 'Cosign',
        )
    );

    public function __construct()
    {
        parent::__construct();
    }

    public function activate()
    {

        global $tables;

        if (!empty($_SESSION['adminloggedin'])) {
            return;
        }

        //set in lists/admin/?page=configure under the cosign section
        $requiredRealm = getConfig('cosign_realm');

        if ($requiredRealm) {
            if (!(isset($_SERVER['REMOTE_REALM']) && $requiredRealm == $_SERVER['REMOTE_REALM'])) {
                return;
            }
        }

        if (!empty($_SERVER['REMOTE_USER'])) {
            $row = Sql_Fetch_Row_Query(
                sprintf(
                    "SELECT id, password, superuser, privileges
                    FROM {$tables['admin']}
                    WHERE loginname = '%s'
                    AND disabled = 0",
                    sql_escape($_SERVER['REMOTE_USER'])
                )
            );

            if ($row) {
                    list($id, $password, $superuser, $privileges) = $row;
                    $_SESSION['adminloggedin'] = $_SERVER['REMOTE_ADDR'];
                    $_SESSION['logindetails'] = array(
                            'adminname' => $_SERVER['REMOTE_USER'],
                            'id' => $id,
                            'superuser' => $superuser,
                            'passhash' => $password,
                    );

                if ($privileges) {
                        $_SESSION['privileges'] = unserialize($privileges);
                }
            }
        }
    }

    //When user logs out redirect them to the webaccess logout page and then back to here.
    public function logout()
    {
        // this is set in the settings page of phplist: lists/admin/?page=configure under the cosign section
        $cosignLogout = getConfig('cosign_logout');

        //If you don't clear the local session cookie and only redirect the browser to the CoSign logout
        //URL, the CoSign session will still be logged out, but the local session will still be valid for
        //about a minute because the CoSign filter caches the credentials.
        if (isset($_SERVER['COSIGN_SERVICE'])) {
            $service_name = $_SERVER['COSIGN_SERVICE'];
            setcookie( $service_name , "null", time()-1, '/', "", 1 );
        }


        //remove server vars on logout as well.
        $_SERVER['REMOTE_USER'] = "";
        $_SESSION['adminloggedin'] = "";
        $_SESSION['logindetails'] = "";

        //destroy the session
        session_destroy();

        //reroute the app to the proper cosign logout url
        //this is set from above and using the getConfig(); function to retrieve it
        //from lists/admin/?page=configure
        $url = "?http://" . $_SERVER['HTTP_HOST'];
        header( "Location: $cosignLogout$url" );

        //if you don't exit you will not... exit :)
        exit();
    }
}


