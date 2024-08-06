<?php
/**
 * COmanage Registry CADRE Authenticator Controller
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
 * @package       registry
 * @since         COmanage Registry v4.1.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

App::uses("SAuthController", "Controller");

class CadreAuthenticatorsController extends SAuthController {
  // Class name, used by Cake
  public $name = "CadreAuthenticators";
  
  public $edit_contains = array();
  
  public $view_contains = array();
  
  /**
   * Callback after controller methods are invoked but before views are rendered.
   * - precondition: Request Handler component has set $this->request->params
   * - postcondition: $cous may be set.
   * - postcondition: $co_groups may be set.
   *
   * @since  COmanage Registry v4.1.0
   */

  function beforeRender() {
    parent::beforeRender();
    
    // Provide a list of message templates
    $args = array();
    $args['conditions']['co_id'] = $this->cur_co['Co']['id'];
    $args['conditions']['status'] = SuspendableStatusEnum::Active;
    $args['conditions']['context'] = array(
      MessageTemplateEnum::Authenticator
    );
    $args['fields'] = array(
      'CoMessageTemplate.id',
      'CoMessageTemplate.description',
      'CoMessageTemplate.context'
    );

    $this->set('vv_message_templates',
               $this->CadreAuthenticator->CoMessageTemplate->find('list', $args));
    
    if(!empty($this->viewVars['cadre_authenticators'])) {
      // Construct the SSR initiation URL
      $url = array(
        'plugin'          => 'cadre_authenticator',
        'controller'      => 'cadres',
        'action'          => 'ssr',
        'authenticatorid' => $this->viewVars['cadre_authenticators'][0]['CadreAuthenticator']['authenticator_id']
      );
      
      $this->set('vv_ssr_initiation_url', Router::url($url, true));

      // Construct the Username Reminder URL, reusing the array from above and changing the action
      $url['action'] = 'remind';
      $this->set('vv_username_reminder_url', Router::url($url, true));
    }

    if(!$this->request->is('restful')) {
      $this->set('vv_email_types', $this->CadreAuthenticator->Authenticator->Co->CoPerson->EmailAddress->types($this->cur_co['Co']['id'], 'type'));
    }
  }
  
  /**
   * Authorization for this Controller, called by Auth component
   * - precondition: Session.Auth holds data used for authz decisions
   * - postcondition: $permissions set with calculated permissions
   *
   * @since  COmanage Registry v4.1.0
   * @return Array Permissions
   */
  
  function isAuthorized() {
    $roles = $this->Role->calculateCMRoles();
    
    // Construct the permission set for this user, which will also be passed to the view.
    $p = array();
    
    // Determine what operations this user can perform
    
    // Edit an existing CadreAuthenticator?
    $p['edit'] = ($roles['cmadmin'] || $roles['coadmin']);
    
    // View all existing CadreAuthenticators?
    $p['index'] = ($roles['cmadmin'] || $roles['coadmin']);
    
    // View an existing CadreAuthenticator?
    $p['view'] = ($roles['cmadmin'] || $roles['coadmin']);
    
    $this->set('permissions', $p);
    return($p[$this->action]);
  }
}
