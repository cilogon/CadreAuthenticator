<?php
/**
 * COmanage Registry Cadre Authenticator Model
 *
 * Portions licensed to the University Corporation for Advanced Internet
 * Development, Inc. ("UCAID") under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @link          http://www.internet2.edu/comanage COmanage Project
 * @package       registry-plugin
 * @since         COmanage Registry v4.1.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

App::uses("AuthenticatorBackend", "Model");

class CadreAuthenticator extends AuthenticatorBackend {
  // Define class name for cake
  public $name = "CadreAuthenticator";

  // Required by COmanage Plugins
  public $cmPluginType = "authenticator";

  // Add behaviors
  public $actsAs = array('Containable');

  // Document foreign keys
  public $cmPluginHasMany = array(
    "CoPerson" => array("Cadre"),
    "CoMessageTemplate" => array("CadreAuthenticator")
  );

  // Association rules from this model to other models
  public $belongsTo = array(
    "Authenticator",
    "CoMessageTemplate"
  );

  public $hasMany = array(
    "CadreAuthenticator.Cadre",
    "CadreAuthenticator.CadreResetToken"
  );

  // Default display field for cake generated views
  public $displayField = "server_id";

  // Request SQL servers
  public $cmServerType = ServerEnum::SqlServer;

  // Validation rules for table elements
  public $validate = array(
    'authenticator_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'server_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'email_type' => array(
      'content' => array(
        'rule' => array('validateExtendedType',
                        array('attribute' => 'EmailAddress.type',
                              'default' => array(EmailAddressEnum::Delivery,
                                                 EmailAddressEnum::Forwarding,
                                                 EmailAddressEnum::MailingList,
                                                 EmailAddressEnum::Official,
                                                 EmailAddressEnum::Personal,
                                                 EmailAddressEnum::Preferred,
                                                 EmailAddressEnum::Recovery))),
        'required' => true,
        'allowEmpty' => false
      )
    ),
    'min_length' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'max_length' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'enable_ssr' => array(
      'rule' => array('boolean'),
      'required' => false,
      'allowEmpty' => true
    ),
    'ssr_validity' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    // XXX This should be required if enable_ssr is true, but for now we don't
    // have a conditional validation rule
    'co_message_template_id' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'redirect_on_success_ssr' => array(
      'rule' => array('url', true),
      'required' => false,
      'allowEmpty' => true
    )
  );

  // Do we support multiple authenticators per instantiation?
  public $multiple = false;
  
  /**
   * Expose menu items.
   * 
   * @ since COmanage Registry v4.1.0
   * @ return Array with menu location type as key and array of labels, controllers, actions as values.
   */

  public function cmPluginMenus() {
    return array();
  }

  /**
   * Obtain current data suitable for passing to manage().
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $backendId  Authenticator Backend ID
   * @param  integer $coPersonId CO Person ID
   * @return Array 
   * @throws RuntimeException
   */

  public function current($id, $backendId, $coPersonId) {
    // Since CADRE principal passwords are only stored in the remote SQL server
    // and not in a database table we need to overload this method from
    // the parent AuthenticatorBackend model.

    $data = array();
    $data['Cadre']['co_person_id'] = $coPersonId;

    return $data;
  }

  /**
   * Lock Authenticator.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  public function lock($id, $coPersonId) {
    return $this->lockOrUnlock($id, $coPersonId, true);
  }

  /**
   * Lock or unlock Authenticator.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @param  Boolean $lock true to disable account or false to enable
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  private function lockOrUnlock($id, $coPersonId, $lock=true) {
    $args = array();
    $args['conditions']['Authenticator.id'] = $id;
    $args['contain'] = 'CadreAuthenticator';

    $authenticator = $this->Authenticator->find('first', $args);

    $sqlServerId = $authenticator['CadreAuthenticator']['server_id'];
    $emailType = $authenticator['CadreAuthenticator']['email_type'];

    // Find the email from the CO Person record.

    $args = array();
    $args['conditions']['EmailAddress.co_person_id'] = $coPersonId;
    $args['conditions']['EmailAddress.type'] = $emailType;
    $args['contain'] = false;

    $emailAddress = $this->Authenticator->Co->CoPerson->EmailAddress->find('first', $args);

    if(empty($emailAddress)) {
      $msg = _txt('pl.cadreauthenticator.email_type.not.found', array($emailType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $email = $emailAddress['EmailAddress']['mail'];

    // Open a connection to the SQL server.
    try {
      $this->Authenticator->Co->Server->SqlServer->connect($sqlServerId, "targetdb");
    } catch (Exception $e) {
      $msg = "Unable to connect to SQL server: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Define our User model.
    $User = new Model(array(
      'table' => 'users',
      'name'  => 'User',
      'ds'    => 'targetdb'
    ));

    $User->clear();

    // Find the current user object.
    $args = array();
    $args['User']['email'] = $email;

    $userObj = $User->find('first', $args);

    if(empty($userObj)) {
      $msg = _txt('pl.cadreauthenticator.email.not.found');
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    if($lock) {
      $userObj['User']['disabled'] = true;
    } else {
      $userObj['User']['disabled'] = false;
    }

    $User->clear();

    if(!$User->save($userObj, false)) {
      $msg = "Unable to save to SQL server: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    return true;
  }
  
  /**
   * Manage Authenticator data, as submitted from the view.
   *
   * @since  COmanage Registry v4.1.0
   * @param  Array   $data            Array of Authenticator data submitted from the view
   * @param  integer $actorCoPersonId Actor CO Person ID
   * @param  boolean $initialPasswordEvent Whether this is the user setting initial password
   * @return string Human readable (localized) result comment
   * @throws InvalidArgumentException
   * @throws RuntimeException
   */

  public function manage($data, $actorCoPersonId, $initialPasswordEvent=false) {
    if(!empty($data['Cadre']['token'])) {
      // Me're here from a Self Service Password Reset operation (ssr), which
      // means all we have are the token and the new password. First, we'll need
      // to pull our own configuration, by looking up the token. 
      
      $args = array();
      $args['conditions']['CadreResetToken.token'] = $data['Cadre']['token'];
      $args['contain'] = array('CadreAuthenticator' => 'Authenticator');
      
      $token = $this->CadreResetToken->find('first', $args);
      
      if(empty($token)) {
        throw new InvalidArgumentException(_txt('er.cadreauthenticator.token.notfound'));
      }
      
      // We can set our configuration based on $token, though note the containable
      // result will be a slightly different structure than we normally get so
      // we have to fix that here.
      
      $this->pluginCfg['CadreAuthenticator'] = $token['CadreAuthenticator'];
      $this->pluginCfg['Authenticator'] = $token['CadreAuthenticator']['Authenticator'];
      unset($this->pluginCfg['CadreAuthenticator']['Authenticator']);
      
      // Stuff additional info we need into $data
      $data['Cadre']['co_person_id'] = $token['CadreResetToken']['co_person_id'];
      $data['Cadre']['cadre_authenticator_id'] = $this->pluginCfg['CadreAuthenticator']['id'];
      
      // Force the $actorCoPersonId to be the CO Person ID associated with the token.
      $actorCoPersonId = $token['CadreResetToken']['co_person_id'];
    }
    
    $minlen = $this->pluginCfg['CadreAuthenticator']['min_length'] ?: 8;
    $maxlen = $this->pluginCfg['CadreAuthenticator']['max_length'] ?: 64;

    // Check minimum length
    if(strlen($data['Cadre']['password']) < $minlen) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.len.min', array($minlen)));
    }

    // Check maximum length
    if(strlen($data['Cadre']['password']) > $maxlen) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.len.max', array($maxlen)));
    }

    // Check that passwords match
    if($data['Cadre']['password'] != $data['Cadre']['password2']) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.match'));
    }
    
    // Make sure we have a CO Person ID to operate over
    if(empty($data['Cadre']['co_person_id'])) {
      throw new InvalidArgumentException(_txt('er.notprov.id', array(_txt('ct.co_people.1'))));
    }

    $coPersonId = $data['Cadre']['co_person_id'];

    // Find the email from the CO Person record.

    $emailType = $this->pluginCfg['CadreAuthenticator']['email_type'];

    $args = array();
    $args['conditions']['EmailAddress.co_person_id'] = $coPersonId;
    $args['conditions']['EmailAddress.type'] = $emailType;
    $args['contain'] = false;

    $emailAddress = $this->Authenticator->Co->CoPerson->EmailAddress->find('first', $args);

    if(empty($emailAddress)) {
      $msg = _txt('pl.cadreauthenticator.email_type.not.found', array($emailType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $email = $emailAddress['EmailAddress']['mail'];

    // Open a connection to the SQL server.
    $sqlServerId = $this->pluginCfg['CadreAuthenticator']['server_id'];

    try {
      $this->Authenticator->Co->Server->SqlServer->connect($sqlServerId, "targetdb");
    } catch (Exception $e) {
      $msg = "Unable to connect to SQL server: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Define our User model.
    $User = new Model(array(
      'table' => 'users',
      'name'  => 'User',
      'ds'    => 'targetdb'
    ));

    $User->clear();

    // Find the current user object, if any.
    $args = array();
    $args['conditions']['User.email'] = $email;
    $args['contain']  = false;

    $userObj = $User->find('first', $args);

    // Check if the user is disabled in the database.
    if(!empty($userObj)) {
      $disabled = $userObj['disabled'] ?? false;
      if($disabled) {
        $msg = _txt('pl.cadreauthenticator.email.disabled', array($email));
        $this->log($msg);
        throw new RuntimeException($msg);
      }
    }

    if(!empty($data['Cadre']['token'])) {
      // If we have a token, validate it before processing anything
      
      // This will throw InvalidArgumentException on error
      $this->CadreResetToken->validateToken($data['Cadre']['token'], false);
    } else {
      // If the actor is the CO Person then the current password is
      // required, so test that it is valid.
      if(($coPersonId == $actorCoPersonId) && !$initialPasswordEvent) {
        if(empty($userObj)) {
          $msg = _txt('pl.cadreauthenticator.email.not.found', array($email));
          $this->log($msg);
          throw new RuntimeException($msg);
        }

        $savedHash = $userObj['User']['passwordhash'] ?? null;
        $verified = password_verify($data['Cadre']['passwordc'], $savedHash);

        if(!$verified) {
          throw new InvalidArgumentException(_txt('er.cadreauthenticator.current'));
        }
      }
    }

    // Set the password.
    try {

      $User->clear();

      $args = array();
      $args['User']['email'] = $email;
      $args['User']['passwordhash'] = password_hash($data['Cadre']['password'], PASSWORD_DEFAULT);
      $args['User']['disabled'] = false;

      if(!empty($userObj)) {
        $args['User']['id'] = $userObj['User']['id'];
        $args['User']['modified'] = date("Y-m-d H:i:s");
      }

      if(!$User->save($args, false)) {
        $msg = "Unable to save to SQL server: ";
        $msg = $msg . print_r($e->getMessage(), true);
        $this->log($msg);
        throw new RuntimeException($msg);
      }

      // Success so now invalidate the token if we had one.
      if(!empty($data['Cadre']['token'])) {
        $this->CadreResetToken->validateToken($data['Cadre']['token'], true);
      }

    } catch (Exception $e) {
      $msg = "Unable to set password for email $email: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    // Compute comment used for flash and for history record.
    $comment = _txt('pl.cadreauthenticator.saved',
                    array($this->pluginCfg['Authenticator']['description']));

    // Write a history record for the CO Person.
    $this->Authenticator
         ->Co
         ->CoPerson
         ->HistoryRecord->record($coPersonId,
                                 null,
                                 null,
                                 $actorCoPersonId,
                                 ActionEnum::AuthenticatorEdited,
                                 $comment,
                                 null, null, null, null, null);

    // We need to manually trigger notification.
    if($actorCoPersonId == $coPersonId) {
      $this->notify($data['Cadre']['co_person_id']);
    }

    return $comment;
  }

  /**
   * Generate a random string, using a cryptographically secure 
   * pseudorandom number generator (random_int)
   *
   * This function requires PHP 7+.
   * 
   * @param int $length      How many characters do we want?
   * @param string $keyspace A string of all possible characters to select from
   * @return string
   */

  function random_str(int $length = 64, string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') {
      if ($length < 1) {
          throw new RangeException("Length must be a positive integer");
      }

      $pieces = [];

      $max = mb_strlen($keyspace, '8bit') - 1;

      for ($i = 0; $i < $length; ++$i) {
          $pieces []= $keyspace[random_int(0, $max)];
      }

      return implode('', $pieces);
  }

  /**
   * Reset Authenticator data for a CO Person.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $coPersonId      CO Person ID
   * @param  integer $actorCoPersonId Actor CO Person ID
   * @param  integer $actorApiUserId  Actor API User ID
   * @return boolean true on success
   */
  
  public function reset($coPersonId, $actorCoPersonId, $actorApiUserId=null) {
    // Perform the reset by reseting the password to a long random string.

    $args = array();
    $args['conditions']['Cadre.cadre_authenticator_id'] = $this->pluginCfg['CadreAuthenticator']['id'];
    $args['conditions']['Cadre.co_person_id'] = $coPersonId;

    // Find the email.
    $emailType = $this->pluginCfg['CadreAuthenticator']['email_type'];

    $args = array();
    $args['conditions']['EmailAddress.co_person_id'] = $coPersonId;
    $args['conditions']['EmailAddress.type'] = $emailType;
    $args['contain'] = false;

    $emailAddress = $this->Authenticator->Co->CoPerson->EmailAddress->find('first', $args);

    if(empty($emailAddress)) {
      $msg = _txt('pl.cadreauthenticator.email_type.not.found', array($emailType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $email = $emailAddress['EmailAddress']['mail'];

    // Open a connection to the SQL server.
    $sqlServerId = $this->pluginCfg['CadreAuthenticator']['server_id'];

    try {
      $this->Authenticator->Co->Server->SqlServer->connect($sqlServerId, 'targetdb');
    } catch (Exception $e) {
      $msg = "Unable to connect to SQL server: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Define our User model.
    $User = new Model(array(
      'table' => 'users',
      'name'  => 'User',
      'ds'    => 'targetdb'
    ));

    $User->clear();

    // Find the user object.
    $args = array();
    $args['User']['email'] = $email;

    $userObj = $User->find('first', $args);

    if(empty($userObj)) {
      $msg = _txt('pl.cadreauthenticator.email.not.found', array($email));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $newRandomPassword = $this->random_str();

    // Change the password.
    try {
      $userObj['User']['passwordhash'] = password_hash($newRandomPassword, PASSWORD_DEFAULT);
      $userObj['User']['modified'] = date("Y-m-d H:i:s");
      // TODO check save
      $User->save($userObj, false);
    } catch (Exception $e) {
      $msg = "Unable to set password for email $email: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }
    
    // And record some history

    $comment = _txt('pl.cadreauthenticator.reset',
                    array($this->pluginCfg['Authenticator']['description']));

    $this->Authenticator
         ->Co
         ->CoPerson
         ->HistoryRecord->record($coPersonId,
                                 null,
                                 null,
                                 $actorCoPersonId,
                                 ActionEnum::AuthenticatorDeleted,
                                 $comment,
                                 null, null, null, null,
                                 $actorApiUserId);

    // We always return true
    return true;
  }

  /**
   * Obtain the current Authenticator status for a CO Person.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $coPersonId   CO Person ID
   * @return Array Array with values
   *               status: AuthenticatorStatusEnum
   *               comment: Human readable string, visible to the CO Person
   * @throws RuntimeException if unable to connect to KDC
   */

  public function status($coPersonId) {
    // Is there a password for this person?
    $emailType = $this->pluginCfg['CadreAuthenticator']['email_type'];

    // Find the email.
    $args = array();
    $args['conditions']['EmailAddress.co_person_id'] = $coPersonId;
    $args['conditions']['EmailAddress.type'] = $emailType;
    $args['contain'] = false;

    $emailAddress = $this->Authenticator->Co->CoPerson->EmailAddress->find('first', $args);

    if(empty($emailAddress)) {
      return array(
        'status' => AuthenticatorStatusEnum::NotSet,
        'comment' => _txt('pl.cadreauthenticator.email_type.not.found', array($emailType))
      );
    }

    $email = $emailAddress['EmailAddress']['mail'];

    $sqlServerId = $this->pluginCfg['CadreAuthenticator']['server_id'];

    try {
      $this->Authenticator->Co->Server->SqlServer->connect($sqlServerId, 'targetdb');
    } catch (Exception $e) {
      $msg = "Unable to connect to SQL server: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Define our User model.
    $User = new Model(array(
      'table' => 'users',
      'name'  => 'User',
      'ds'    => 'targetdb'
    ));

    $User->clear();

    try {
      // Find the current user object, if any.
      $args = array();
      $args['User']['email'] = $email;

      $userObj = $User->find('first', $args);
    } catch (Exception $e) {
      $userObj = null;
    }

    if(empty($userObj)) {
      return array(
        'status' => AuthenticatorStatusEnum::NotSet,
        'comment' => _txt('pl.cadreauthenticator.email.not.found', array($email))
      );
    }

    if(!empty($userObj['disabled'])) {
      if($userObj['disabled']) {
        return array(
          'status' => AuthenticatorStatusEnum::Locked,
          'comment' => _txt('pl.cadreauthenticator.email.disabled', array($email))
        );
      }
    } else {
      $lastModificationTime = $userObj['User']['modified'];
      $lastModificationDateTime = new DateTime("$lastModificationTime");
      $lastModificationString = $lastModificationDateTime->format('Y-m-d H:i:s');
      return array(
        'status' => AuthenticatorStatusEnum::Active,
        'comment' => _txt('pl.cadreauthenticator.mod', array($lastModificationString))
      );
    }
  }

  /**
   * Unlock Authenticator
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  public function unlock($id, $coPersonId) {
    return $this->lockOrUnlock($id, $coPersonId, false);
  }
}
