<?php
/**
 * COmanage Registry CADRE Password Reset Token Model
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
 * @since         COmanage Registry v4.0.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

class CadreResetToken extends AppModel {
  // Define class name for cake
  public $name = "CadreResetToken";

  // Current schema version for API
  public $version = "1.0";
  
  // Add behaviors
  public $actsAs = array('Containable',
                         'Changelog' => array('priority' => 5));

  // Association rules from this model to other models
  public $belongsTo = array(
    "CadreAuthenticator.CadreAuthenticator",
    "CoPerson"
  );

  // Default display field for cake generated views
  public $displayField = "co_person_id";

  // Validation rules for table elements
  public $validate = array(
    'cadre_authenticator_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'co_person_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'token' => array(
      'rule' => 'notBlank',
      'required' => true,
      'allowEmpty' => false
    ),
    'expires' => array(
      'rule' => '/.*/',  // The 'date' rule is too constraining
      'required' => true,
      'allowEmpty' => false
    )
  );
  
  /**
   * Generate a CADRE password reset token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  int    $cadreAuthenticatorId Cadre Authenticator ID
   * @param  int    $coPersonId              CO Person ID
   * @return string                          Service Token
   * @throws InvalidArgumentException
   * @throws RuntimeException
   */

  protected function generate($cadreAuthenticatorId, $coPersonId) {
    // Toss any previous reset tokens. We need to fire callbacks for ChangelogBehavior.
    $args = array(
      'CadreResetToken.cadre_authenticator_id' => $cadreAuthenticatorId,
      'CadreResetToken.co_person_id' => $coPersonId
    );
    
    $this->deleteAll($args, true, true);

    // We need the token validity configuration
    $tokenValidity = $this->CadreAuthenticator->field('ssr_validity', array('CadreAuthenticator.id' => $cadreAuthenticatorId));
    
    if(!$tokenValidity) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.cadre_authenticators.1'), $cadreAuthenticatorId)));
    }
    
    $token = generateRandomToken();
    
    $data = array(
      'CadreResetToken' => array(
        'cadre_authenticator_id' => $cadreAuthenticatorId,
        'co_person_id'              => $coPersonId,
        'token'                     => $token,
        'expires'                   => date('Y-m-d H:i:s', strtotime('+' . $tokenValidity . ' minutes'))
      )
    );

    $this->clear();
    
    if(!$this->save($data)) {
      throw new RuntimeException(_txt('er.db.save-a', array('CadreResetToken::generate')));
    }
    
    return $token;
  }
  
  /**
   * Attempt to generate (and send) a CADRE password reset token request or UserName Reminder
   *
   * @since  COmanage Registry v4.1.0
   * @param  int    $authenticatorId Authenticator ID
   * @param  string $q               Search query (email or identifier)
   * @param  string $mode	     'reset' for ssr or 'remind' for username reminder
   * @return bool                    True on success
   * @throws InvalidArgumentException
   */
  
  public function generateRequest($authenticatorId, $q, $mode='reset') {
    // First, search for a CO Person record that matches $q. Note that both
    // EmailAddress and Identifier implement exact searching only, so we don't
    // need to handle that specially here. We do need to know the CO to search
    // within, though.
    
    $coId = $this->CadreAuthenticator->Authenticator->field('co_id', array('Authenticator.id' => $authenticatorId));
    
    if(!$coId) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.authenticators.1'), $authenticatorId)));
    }
    
    // Next, try to find a CO Person ID. 
    
    $coPersonId = null;
    
    foreach(array('EmailAddress') as $model) {
      // Note this search will match _unverified_ email addresses, but we only
      // want to match verified email addresses. We'll filter those below.
      $matches = $this->CoPerson->$model->search($coId, $q, 25);
      
      if(!empty($matches)) {
        foreach($matches as $m) {
          // We only want to find Active COPerson records.
          if(isset($m['CoPerson']['status']) && $m['CoPerson']['status'] != StatusEnum::Active) {
             continue;
          }
          // If this is an EmailAddress, make sure it is verified
          if(isset($m['EmailAddress']['verified']) && !$m['EmailAddress']['verified']) {
            continue;
          }
          
          if(!$coPersonId) {
            $coPersonId = $m['CoPerson']['id'];
          } elseif($coPersonId != $m['CoPerson']['id']) {
            // We found at least two different CO People, so throw an error
            throw new InvalidArgumentException(_txt('er.cadreauthenticator.ssr.multiple', array($q)));
          }
        }
      }
    }
    
    if(!$coPersonId) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.ssr.notfound', array($q)));
    }
    
    // Take the CO Person and look for associated verified email addresses.
    // This could match the search query, but we'll walk the path to make sure.
    
    $args = array();
    $args['conditions']['CoPerson.id'] = $coPersonId;
    $args['contain'] = array('EmailAddress');

    $coPerson = $this->CoPerson->find('first', $args);
    
    // We could try prioritizing on type or something, but instead we'll just
    // send the message to however many verified addresses we find.
    $verifiedEmails = array();
    
    if(!empty($coPerson['EmailAddress'])) {
      foreach($coPerson['EmailAddress'] as $ea) {
        if($ea['verified']) {
          $verifiedEmails[] = $ea['mail'];
        }
      }
    }
    
    if(empty($verifiedEmails)) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.ssr.notfound', array($q)));
    }
    
    // Map the Authenticator ID to a CADRE Authenticator ID
    $args = array();
    $args['conditions']['CadreAuthenticator.authenticator_id'] = $authenticatorId;
    $args['contain'] = false;
    
    $cadreAuthenticator = $this->CadreAuthenticator->find('first', $args);
    
    if(!$cadreAuthenticator) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.authenticators.1'), $authenticatorId)));
    }
    
    // Use $mode to determine whether we're sending Reset Token Request or Username Reminder
    // and send the message
    if( $mode == 'reset') {
      //  generate a token in order to send it
      $token = $this->generate($cadreAuthenticator['CadreAuthenticator']['id'], $coPersonId);
    
      $this->sendRequest($cadreAuthenticator, $coPerson, $token, $verifiedEmails, $coPersonId);
    } elseif( $mode == 'remind') {
      $this->send($cadreAuthenticator, $coPerson, $verifiedEmails, $coPersonId, array(), 'remind');
    }
    return true;
  }
  
  /**
   * Send a CADRE password reset token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  CadreAuthenticator $cadreAuthenticator CADRE Authenticator configuration
   * @param  array                 $coPerson              CO Person with associated email addresses and identifiers
   * @param  string                $token                 Password Reset Token
   * @param  array                 $recipients            Array of email addresses to send token to
   * @param  int                   $actorCoPersonId       Actor CO Person ID
   * @throws InvalidArgumentException
   */
  
  protected function sendRequest($cadreAuthenticator, $coPerson, $token, $recipients, $actorCoPersonId) {

    // get the expiration time
    $expiry = $this->field('expires', array('CadreResetToken.token' => $token));
    
    // set substitutions
    $rurl = array(
      'plugin'      => 'cadre_authenticator',
      'controller'  => 'cadres',
      'action'      => 'ssr',
      'token'       => $token
    );

    $substitutions = array(
      'RESET_URL'         => Router::url($rurl, true),
      'LINK_EXPIRY'       => $expiry
    );

    $this->send($cadreAuthenticator, $coPerson, $recipients, $actorCoPersonId, $substitutions, 'reset');

    // Also store the recipient list in the token
    $this->clear();
    $this->updateAll(
      array('CadreResetToken.recipients' => "'" . substr(implode(',', $recipients), 0, 256) . "'"),
      array('CadreResetToken.token' => "'" . $token . "'")
    );
  }

  /**
   * Send a Password Reset  or Username Reminder
   *
   * @since  COmanage Registry v4.1.0
   * @param  CadreAuthenticator $cadreAuthenticator CADRE Authenticator configuration
   * @param  array                 $coPerson              CO Person with associated email addresses and identifiers
   * @param  array                 $recipients            Array of email addresses to send token to
   * @param  int                   $actorCoPersonId       Actor CO Person ID
   * @param  array		   $substitutions	  substitutions for the message template
   * @param  string		   $mode		  'reset' for ssr or 'remind' for username reminder
   * @throws InvalidArgumentException
   */
  protected function send($cadreAuthenticator, $coPerson, $recipients, $actorCoPersonId, $substitutions=array(), $mode='reset') {

    // Use the value of $mode to set the message template type and text for history record
    $mtType = null;
    $historyText = null;

    if ($mode == 'remind') {
      $mtType = 'username_reminder_message_template_id';
      $historyText = 'pl.cadreauthenticator.usernamereminder.hr.sent';
      $substitutions = array();
      $substitutions['EMAIL_ADDRESS'] = $coPerson['EmailAddress'][0]['mail'];
    } elseif($mode == 'reset') {
      $mtType = 'co_message_template_id';
      $historyText = 'pl.cadreauthenticator.ssr.hr.sent';
    }

    // Pull the message template
    $mt = null;

    if(!empty($cadreAuthenticator['CadreAuthenticator'][$mtType])) {
      $args = array();
      $args['conditions']['CoMessageTemplate.id'] = $cadreAuthenticator['CadreAuthenticator'][$mtType];
      $args['conditions']['CoMessageTemplate.status'] = SuspendableStatusEnum::Active;
      $args['contain'] = false;

      $mt = $this->CadreAuthenticator->CoMessageTemplate->find('first', $args);
    }

    if(empty($mt)) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.co_message_templates.1'), $cadreAuthenticator['CadreAuthenticator'][$mtType])));
    }

    $ids = array();

    $msgSubject = processTemplate($mt['CoMessageTemplate']['message_subject'], $substitutions, $ids);
    $format = $mt['CoMessageTemplate']['format'];
    
    // We don't try/catch, but instead let any exceptions bubble up.
    $email = new CakeEmail('default');

      // If a from address was provided, use it
/*
      if($fromAddress) {
        $email->from($fromAddress);
      }*/

    // Add cc and bcc if specified
    if($mt['CoMessageTemplate']['cc']) {
      $email->cc(explode(',', $mt['CoMessageTemplate']['cc']));
    }

    if($mt['CoMessageTemplate']['bcc']) {
      $email->bcc(explode(',', $mt['CoMessageTemplate']['bcc']));
    }
    
    $msgBody = array();
    
    if($format != MessageFormatEnum::Plaintext
       && !empty($mt['CoMessageTemplate']['message_body_html'])) {
      $msgBody[MessageFormatEnum::HTML] = processTemplate($mt['CoMessageTemplate']['message_body_html'], $substitutions, $ids);
    }
    if($format != MessageFormatEnum::HTML
       && !empty($mt['CoMessageTemplate']['message_body'])) {
      $msgBody[MessageFormatEnum::Plaintext] = processTemplate($mt['CoMessageTemplate']['message_body'], $substitutions, $ids);
    }
    if(empty($msgBody[MessageFormatEnum::Plaintext])) {
      $msgBody[MessageFormatEnum::Plaintext] = "unknown message";
    }
    
    $email->template('custom', 'basic')
      ->emailFormat($format)
      ->to($recipients)
      ->viewVars($msgBody)
      ->subject($msgSubject);
    $email->send();
    
    // Record a HistoryRecord
    $this->CoPerson->HistoryRecord->record($coPerson['CoPerson']['id'],
                                           null,
                                           null,
                                           $actorCoPersonId,
                                           ActionEnum::AuthenticatorEdited,
                                           _txt($historyText, array(implode(",", $recipients))));
  }
  
  /**
   * Validate a Password Reset Token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  string  $token      Password Reset Token
   * @param  boolean $invalidate If true, invalidate the token (otherwise just test it)
   * @return int                 CO Person ID
   * @throws InvalidArgumentException
   */
  
  public function validateToken($token, $invalidate=true) {
    if(!$token) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.token.notfound'));
    }
    
    $args = array();
    $args['conditions']['CadreResetToken.token'] = $token;
    $args['contain'] = array('CoPerson', 'CadreAuthenticator');
    
    $token = $this->find('first', $args);

    if(empty($token) || empty($token['CadreResetToken']['co_person_id'])) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.token.notfound'));
    }
    
    if(time() > strtotime($token['CadreResetToken']['expires'])) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.token.expired'));
    }
    
    // We only accept validation requests for Active or Grace Period CO People.
    if(!in_array($token['CoPerson']['status'], array(StatusEnum::Active, StatusEnum::GracePeriod))) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.ssr.inactive'));
    }
    
    // We won't validate locked tokens, so check the Authenticator Status
    $args = array();
    $args['conditions']['AuthenticatorStatus.co_person_id'] = $token['CadreResetToken']['co_person_id'];
    $args['conditions']['AuthenticatorStatus.authenticator_id'] = $token['CadreAuthenticator']['authenticator_id'];
    $args['contain'] = false;
    
    $locked = $this->CoPerson->AuthenticatorStatus->field('locked', $args['conditions']);
    
    if($locked) {
      throw new InvalidArgumentException(_txt('er.cadreauthenticator.ssr.locked'));
    }
    
    if($invalidate) {
      // We could also delete the token if it was expired, but that might cause
      // user confusion when their error changes from "expired" to "notfound",
      // and deleting the token doesn't actually remove the row from the table.
      
      $this->delete($token['CadreResetToken']['id']);
    }
    
    return $token['CadreResetToken']['co_person_id'];
  }
}
