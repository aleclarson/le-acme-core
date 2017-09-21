/*!
 * le-acme-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var registerNewAccount = require('./lib/register-new-account');
var getCertificate = require('./lib/get-certificate');
var getAcmeUrls = require('./lib/get-acme-urls');

var knownEndpoints = ['new-authz', 'new-cert', 'new-reg', 'revoke-cert', 'key-change'];
var challengeTypes = ['http-01', 'tls-sni-01', 'dns-01'];

var defaults = {
  stagingServerUrl: 'https://acme-staging.api.letsencrypt.org/directory',
  productionServerUrl: 'https://acme-v01.api.letsencrypt.org/directory',
  acmeChallengePrefix: '/.well-known/acme-challenge/',
  knownEndpoints: ['new-authz', 'new-cert', 'new-reg', 'revoke-cert', 'key-change'],
  challengeTypes: ['http-01', 'tls-sni-01', 'dns-01'],
  challengeType: 'http-01',
  rsaKeySize: 2048,
};

exports.create = function(config) {
  var self = Object.assign({}, defaults);
  return Object.setPrototypeOf(self, {
    getAcmeUrls: getAcmeUrls.create(config),
    getCertificate: getCertificate.create(config),
    registerNewAccount: registerNewAccount.create(config),
  });
};

Object.assign(exports, defaults);
