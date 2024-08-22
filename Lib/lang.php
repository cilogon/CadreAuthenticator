<?php
/**
 * COmanage Registry CADRE Authenticator Plugin Language File
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
  
global $cm_lang, $cm_texts;

// When localizing, the number in format specifications (eg: %1$s) indicates the argument
// position as passed to _txt.  This can be used to process the arguments in
// a different order than they were passed.

$cm_cadre_authenticator_texts['en_US'] = array(
  // Titles, per-controller
  'ct.cadre_authenticators.1'  => 'CADRE Authenticator',
  'ct.cadre_authenticators.pl' => 'CADRE Authenticators',
  'ct.passwords.1'           => 'Password',
  'ct.passwords.pl'          => 'Passwords',
  
  // Error messages
  'er.cadreauthenticator.current'   => 'Current password is not valid',
  'er.cadreauthenticator.match'     => 'New passwords do not match',
  'er.cadreauthenticator.len.max'   => 'Password cannot be more than %1$s characters',
  'er.cadreauthenticator.len.min'   => 'Password must be at least %1$s characters',
  'er.cadreauthenticator.ssr.cfg'   => 'Configuration not supported for Self Service Reset',
  'er.cadreauthenticator.ssr.inactive'   => 'CO Person is not active and Authenticator cannot be reset',
  'er.cadreauthenticator.ssr.locked'     => 'Authenticator is locked and cannot be reset',
  'er.cadreauthenticator.ssr.multiple'   => 'Could not resolve a single CO Person for "%1$s"',
  'er.cadreauthenticator.ssr.notfound'   => 'No verified email address was found for "%1$s"',
  'er.cadreauthenticator.token.expired'  => 'Reset token expired',
  'er.cadreauthenticator.token.notfound' => 'Reset token not found',
  'er.cadreauthenticator.delete.fail'    => 'Error deleting password for %1$s',
  
  // Plugin texts
  'pl.cadreauthenticator.email_type'     => 'Email Type',
  'pl.cadreauthenticator.email_type.desc' => 'Email type used for username',
  'pl.cadreauthenticator.email_type.not.found' => 'Email type %1$s not found',
  'pl.cadreauthenticator.email.not.found' => 'Email %1$s not provisioned',
  'pl.cadreauthenticator.email.disabled' => 'Email %1$s is disabled',
  'pl.cadreauthenticator.generate'       => 'To generate a new token, click the <b>Generate</b> button below. This will replace the existing token, if one was already set.',
  'pl.cadreauthenticator.info'           => 'Your new password must be between %1$s and %2$s characters in length, and include characters from three of the following: lowercase letters, uppercase letters, numbers, and symbols.',
  'pl.cadreauthenticator.maxlen'         => 'Maximum Password Length',
  'pl.cadreauthenticator.maxlen.desc'    => 'Must be between 8 and 64 characters (inclusive), default is 64',
  'pl.cadreauthenticator.minlen'         => 'Minimum Password Length',
  'pl.cadreauthenticator.minlen.desc'    => 'Must be between 8 and 64 characters (inclusive), default is 12',
  'pl.cadreauthenticator.mod'            => 'Password last changed %1$s UTC',
  'pl.cadreauthenticator.noedit'         => 'This password cannot be edited via this interface.',
  'pl.cadreauthenticator.password.again' => 'New Password Again',
  'pl.cadreauthenticator.password.current' => 'Current Password',
  'pl.cadreauthenticator.password.info'  => 'This newly generated password cannot be recovered. If it is lost a new password must be generated. ',
  'pl.cadreauthenticator.password.new'   => 'New Password',
  'pl.cadreauthenticator.password_source' => 'Password Source',
  'pl.cadreauthenticator.remind.q'       => 'Email Address',
  'pl.cadreauthenticator.reset'          => 'Password "%1$s" Reset',
  'pl.cadreauthenticator.saved'          => 'Password "%1$s" Set',
  'pl.cadreauthenticator.ssr'            => 'Enable Self Service Reset',
  'pl.cadreauthenticator.ssr.desc'       => 'Allow self service reset via single use tokens sent to a verified email address',
  'pl.cadreauthenticator.ssr.for'        => 'Select a new password for %1$s.',
  'pl.cadreauthenticator.ssr.hr.sent'    => 'Password reset request sent to "%1$s"',
  'pl.cadreauthenticator.ssr.info'       => 'Enter your email address to proceed.</p>If you still know your password, click <a href="%1$s">here</a> to directly select a new password.',
  'pl.cadreauthenticator.ssr.mt'         => 'Reset Message Template',
  'pl.cadreauthenticator.ssr.mt.desc'    => 'Message template used for email to send reset instructions to',
  'pl.cadreauthenticator.ssr.q'          => 'Email Address',
  'pl.cadreauthenticator.ssr.redirect'   => 'Redirect on Self Service Reset',
  'pl.cadreauthenticator.ssr.redirect.desc' => 'URL to redirect to on successful self service reset',
  'pl.cadreauthenticator.ssr.sent'       => 'An email with further instructions has been sent to the address on record',
  'pl.cadreauthenticator.ssr.url'        => 'Self Service Reset Initiation URL',
  'pl.cadreauthenticator.ssr.validity'   => 'Self Service Reset Token Validity',
  'pl.cadreauthenticator.ssr.validity.desc' => 'Time in minutes the reset token is valid for',
  'pl.cadreauthenticator.token.confirm'  => 'Are you sure you wish to generate a new token?',
  'pl.cadreauthenticator.token.gen'      => 'Generate Token',
  'pl.cadreauthenticator.token.ssr'      => 'Self Service Password Reset',
  'pl.cadreauthenticator.token.usernamereminder' => 'Username Reminder',
  'pl.cadreauthenticator.usernamereminder.info' => 'Enter a verified email address to proceed.',
  'pl.cadreauthenticator.usernamereminder.mt' => 'Username Reminder Message Template',
  'pl.cadreauthenticator.usernamereminder.mt.desc' => 'Message template used for email to send username reminder to',
  'pl.cadreauthenticator.usernamereminder.hr.sent' => 'Username Reminder sent to "%1$s"',
  'pl.cadreauthenticator.usernamereminder.url' => 'Username Reminder URL'
);
