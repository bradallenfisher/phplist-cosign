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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @category  phplist
 * @package   CosignPlugin
 * @author    Duncan Cameron
 * @copyright 2015 Duncan Cameron
 * @license   http://www.gnu.org/licenses/gpl.html GNU General Public License, Version 3
 */

 /**
 * Registers the plugin with phplist
 */

class CosignPlugin extends phplistPlugin
{
  const VERSION_FILE = 'version.txt';
  const PLUGIN = 'CosignPlugin';

  /*
   *  Inherited variables
  */
  public $name = 'Cosign Plugin';
  public $authors = 'Duncan Cameron, Brad Allen Fisher';
  public $description = 'Use Cosign SSO to authenticate administrators';
  public $enabled = 1;

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
      'description' => 'the address that will log you out of your cosign session',
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

    // if your browser is still carrying around the cookie, you will be logged right back in after logout
    // so destroy it.
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
    header( "Location: $cosignLogout" );

    //if you don't exit you will not... exit :)
    exit();
  }
}


