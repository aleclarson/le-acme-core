/*!
 * le-acme-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var assertValid = require('assertValid');
var request = require('request');

exports.create = function(config) {
  var log = config.log;
  return function getAcmeUrls(acmeDiscoveryUrl) {
    assertValid(acmeDiscoveryUrl, 'string');

    var knownUrls = this.knownEndpoints;

    // TODO: Check response header on request for cache time
    return request(acmeDiscoveryUrl).then(function(res) {
      var json;
      try {
        json = res.json;
      } catch(error) {
        error.raw = res.data;
        error.url = acmeDiscoveryUrl;
        error.message += '\nResponse text: ' + res.text +
          '\nRequest url: ' + acmeDiscoveryUrl;

        throw error;
      }

      var missingUrls = [];
      knownUrls.forEach(function(url) {
        json[url] || missingUrls.push(url);
      });
      if (missingUrls.length) {
        log('warn', 'CA does not have these known urls:\n' +
          missingUrls.map(function(url) {
            return '  ' + url;
          }).join('\n'));
      }

      return {
        newAuthz: json['new-authz'],
        newCert: json['new-cert'],
        newReg: json['new-reg'],
        revokeCert: json['revoke-cert'],
        keyChange: json['key-change'],
      };
    });
  };
};
