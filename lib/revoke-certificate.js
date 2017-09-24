/*!
 * le-acme-core
 * Copyright(c) 2017 Alec Larson <alec.stanford.larson@gmail.com>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var assertValid = require('assertValid');
var certUtils = require('cert-utils');
var RSA = require('rsa-utils');

var Acme = require('./acme-client');

var optionTypes = {
  cert: 'string',
  domainKeyPair: 'string|object?',
  accountKeyPair: 'string|object?',
  revokeCertUrl: 'string',
};

exports.create = function(config) {
  var log = config.log;
  return function revokeCertificate(options) {
    assertValid(options, optionTypes);

    if (!options.accountKeyPair && !options.domainKeyPair) {
      throw Error("Must define either `accountKeyPair` or `domainKeyPair`");
    }

    try {
      var acme = new Acme({
        keyPair: options.accountKeyPair || options.domainKeyPair,
        log: log,
      });
    } catch(error) {
      throw Error("Failed to parse private key. " + error.message);
    }

    return certUtils.der(options.cert).then(function(cert) {
      return acme.post(options.revokeCertUrl, {
        resource: 'revoke-cert',
        certificate: RSA.toWebsafeBase64(cert.toString('base64')),
      }).then(function(res) {
        if (!res.success) {
          var error = 'Failed to revoke certificate';
          try {
            error += ': ' + JSON.stringify(res.json, null, 2);
          } catch(e) {}
          throw Error(error);
        }
      });
    });
  };
};
