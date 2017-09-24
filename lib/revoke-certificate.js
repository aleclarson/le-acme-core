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

var optionTypes = {
  cert: 'string',
  publicKeyPem: 'string?',
  accountKeyPair: 'string|object?',
  revokeCertUrl: 'string',
};

exports.create = function(config) {
  var log = config.log;
  return function revokeCertificate(options) {
    assertValid(options, optionTypes);

    if (!options.publicKeyPem && !options.accountKeyPair) {
      throw Error("Must define either `publicKeyPem` or `accountKeyPair`");
    }

    var keyPair = options.accountKeyPair ||
      RSA.import({publicKeyPem: options.publicKeyPem});

    try {
      var acme = new Acme({
        keyPair: keyPair,
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
