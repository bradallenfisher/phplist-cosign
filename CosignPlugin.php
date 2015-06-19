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
 * @author    Duncan Cameron, Brad Allen Fisher
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
    //var_dump($_SERVER);
    //var_dump($_SESSION);

    global $tables;

    if (!empty($_SESSION['adminloggedin'])) {
      return;
    }

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
    $cosignLogout = getConfig('cosign_logout');

    if (isset($_SERVER['COSIGN_SERVICE'])) {
      $service_name = $_SERVER['COSIGN_SERVICE'];
      setcookie( $service_name , "null", time()-1, '/', "", 1 );
    }

    $_SERVER['REMOTE_USER'] = "";
    $_SESSION['adminloggedin'] = "";
    $_SESSION['logindetails'] = "";
    session_destroy();


    header( "Location: $cosignLogout" );
    exit();
  }
}


