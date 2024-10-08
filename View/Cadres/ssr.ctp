<?php
/**
 * COmanage Registry CADRE SSR (Self Service Reset) View
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

  $params = array('title' => _txt('pl.cadreauthenticator.token.ssr'));
  print $this->element("pageTitle", $params);
  
  $options = array(
    'type' => 'post',
    'url' => array(
      'plugin'          => 'cadre_authenticator',
      'controller'      => 'cadres',
      'action'          => 'ssr'
    )
  );
  
  if(!empty($this->request->params['named']['authenticatorid'])
     && empty($vv_token)) {
    // Initial "enter an email or identifier" form
    $options['url']['authenticatorid'] = $this->request->params['named']['authenticatorid'];
  }
  
  print $this->Form->create('Cadre', $options);
  
  if(!empty($vv_token)) {
    print $this->Form->hidden('token', array('default' => $vv_token)) . "\n";
  }
?>
<?php if(!empty($this->request->params['named']['authenticatorid']) && empty($vv_token)): ?>
<div class="ui-state-highlight ui-corner-all co-info-topbox">
  <span class="ui-icon ui-icon-info co-info"></span>
  <strong><?php print _txt('pl.cadreauthenticator.ssr.info', array($vv_ssr_authenticated_url)); ?></strong>
</div>

<ul id="<?php print $this->action; ?>_ssr" class="fields form-list">
  <li>
    <div class="field-name vtop">
      <div class="field-title">
        <?php print _txt('pl.cadreauthenticator.ssr.q'); ?>
      </div>
    </div>
    <div class="field-info">
      <?php print $this->Form->input('q', array('label' => false)); ?>
    </div>
  </li>
  <li class="fields-submit">
    <div class="field-name">
      <span class="required"><?php print _txt('fd.req'); ?></span>
    </div>
    <div class="field-info">
      <?php print $this->Form->submit(_txt('op.search')); ?>
    </div>
  </li>
</ul>
<?php elseif(!empty($vv_token)): ?>
<?php if(!empty($vv_name)): ?>
<div class="ui-state-highlight ui-corner-all co-info-topbox">
  <i class="material-icons">info</i>
  <?php print _txt('pl.cadreauthenticator.ssr.for', array($vv_name)); ?>
</div>
<?php endif; // vv_name ?>

<div class="co-info-topbox">
  <i class="material-icons">info</i>
  <?php
    $maxlen = isset($vv_authenticator['CadreAuthenticator']['max_length'])
              ? $vv_authenticator['CadreAuthenticator']['max_length']
              : 64;
    $minlen = isset($vv_authenticator['CadreAuthenticator']['min_length'])
              ? $vv_authenticator['CadreAuthenticator']['min_length']
              : 8;

    print _txt('pl.cadreauthenticator.info', array($minlen, $maxlen));
  ?>
</div>



<ul id="<?php print $this->action; ?>_ssr" class="fields form-list">
  <li>
    <div class="field-name">
      <div class="field-title">
        <?php print _txt('pl.cadreauthenticator.password.new'); ?>
        <span class="required">*</span>
      </div>
    </div>
    <div class="field-info">
      <?php print $this->Form->input('password', array('label' => false)); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title">
        <?php print _txt('pl.cadreauthenticator.password.again'); ?>
        <span class="required">*</span>
      </div>
    </div>
    <div class="field-info">
      <?php print $this->Form->input('password2', array('type' => 'password', 'label' => false)); ?>
    </div>
  </li>
  <li class="fields-submit">
    <div class="field-name">
      <span class="required"><?php print _txt('fd.req'); ?></span>
    </div>
    <div class="field-info">
      <?php print $this->Form->submit(_txt('op.submit')); ?>
    </div>
  </li>
</ul>
<?php endif; // $vv_token ?>
<?php
  print $this->Form->end();
