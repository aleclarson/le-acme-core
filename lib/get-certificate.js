/*!
 * le-acme-core
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var assertValid = require('assertValid');
var request = require('request');
var RSA = require('rsa-utils');

var Acme = require('./acme-client');

var optionTypes = {
  domains: 'array',
  domainKeyPair: 'object',
  accountKeyPair: 'object',
  newAuthzUrl: 'string',
  newCertUrl: 'string',
  setChallenge: 'function', // (hostname, challengeKey, tokenValue, done)
  removeChallenge: 'function', // (hostname, challengeKey, done)
};

exports.create = function(config) {
  var log = config.log;
  return function getCertificate(options) {
    assertValid(options, optionTypes);

    if (!options.challengeType) {
      options.challengeType = 'http-01';
    }
    else if (-1 === this.challengeTypes.indexOf(options.challengeType)) {
      throw Error("Unsupported challenge type: '" + options.challengeType + "'");
    }

    if (!options.domains.length) {
      throw Error("Must provide at least one domain");
    }

    var acme;
    try {
      acme = new Acme(options.accountKeyPair);
    } catch(error) {
      throw Error("Failed to parse private key. " + error.message);
    }

    var state = {
      domains: options.domains.slice(),
      newCertUrl: options.newCertUrl,
      newAuthzUrl: options.newAuthzUrl,
      validatedDomains: [],
      validAuthorizationUrls: [],
    };

    return nextDomain().then(function() {
      var privatePem = RSA.exportPrivatePem(options.domainKeyPair);
      return {
        cert: certBufferToPem(state.certificate),
        privkey: privatePem,
        chain: state.chainPem,
        // TODO: nix backwards compat
        key: privatePem,
        ca: state.chainPem,
      }
    });

    function nextDomain() {
      if (state.domains.length) {
        return getChallenges(state.domains.shift());
      } else {
        var csr = RSA.generateCsrWeb64(options.domainKeyPair, state.validatedDomains);
        log('debug', 'Creating new certificate: ' + state.newCertUrl);
        return acme.post(state.newCertUrl, {
          resource: 'new-cert',
          csr: csr,
          authorizations: state.validAuthorizationUrls,
        }).then(downloadCertificate, function(error) {
          log('debug', 'Failed to create new certificate');
          throw error;
        });
      }
    }

    function getChallenges(domain) {
      state.domain = domain;
      return acme.post(state.newAuthzUrl, {
        resource: 'new-authz',
        identifier: {
          type: 'dns',
          value: domain,
        },
      }).then(getReadyToValidate);
    }

    function getReadyToValidate(res) {
      var links = Acme.parseLink(res.headers.link);
      if (!(links && 'next' in links)) {
        throw Error("CA failed to return url for fetching new certificate");
      }

      state.authorizationUrl = res.headers.location;
      state.newCertUrl = links.next;

      var authz = parseBody(res);
      var challenges = authz.challenges.filter(function(x) {
        return x.type === options.challengeType;
      });
      if (challenges.length === 0) {
        throw Error("Server didn't offer any challenge we can handle");
      }

      var challenge = challenges[0];
      var thumbprint = RSA.thumbprint(options.accountKeyPair);
      var keyAuthorization = challenge.token + '.' + thumbprint;
      var domain = state.domain;
      var token = challenge.token;

      return new Promise(function(resolve) {
        options.setChallenge(domain, token, keyAuthorization, resolve);
      }).then(function() {
        return acme.post(challenge.uri, {
          resource: 'challenge',
          keyAuthorization: keyAuthorization,
        }).then(function(res) {
          return ensureValidation(res, function() {
            options.removeChallenge(domain, token, function() {
              // ignore
            });
          });
        });
      }, function(error) {
        log('debug', '`options.setChallenge` threw an error');
        options.removeChallenge(domain, token, function() {
          // ignore
        });
        throw error;
      });
    }

    function ensureValidation(res, unlink) {
      var authz = parseBody(res);
      switch (authz.status) {

      case 'pending':
        return new Promise(function(resolve, reject) {
          setTimeout(function() {
            request(state.authorizationUrl).then(function(res) {
              return ensureValidation(res, unlink);
            }).then(resolve, reject);
          }, 1000);
        });

      case 'valid':
        log('verbose', 'Validated domain: ' + state.domain);
        state.validatedDomains.push(state.domain);
        state.validAuthorizationUrls.push(state.authorizationUrl);
        unlink();
        return nextDomain();

      case 'invalid':
        unlink();
        var challengesState = (authz.challenges || []).map(function(challenge) {
          var result =  ' - ' + challenge.uri + ' [' + challenge.status + ']';
          return result;
        }).join('\n');
        throw Error(
          'The CA was unable to validate the file you provisioned.\n' +
          (challengesState ? challengesState + '\n' : '') +
          JSON.stringify(authz, null, 2)
        );

      default:
        unlink();
        throw Error(
          "CA returned an authorization in an unexpected state: " +
          JSON.stringify(authz, null, 2)
        );
      }
    }

    function downloadCertificate(res) {
      var links = Acme.parseLink(res.headers.link);
      if (!links || !('up' in links)) {
        throw Error("CA failed to return the 'ca-cert' url");
      }

      var certUrl = res.headers.location;
      state.certificate = parseBody(res);

      log('debug', 'Fetching certificate: ' + certUrl);
      return request(certUrl).then(function(res) {
        var body = parseBody(res);
        if (body.toString() !== state.certificate.toString()) {
          throw Error("Fetched certificate did not match");
        }
      }).catch(function(error) {
        log('debug', 'Failed to verify certificate');
        throw error;
      }).then(function() {
        log('debug', 'Successfully verified certificate');
        return downloadIssuerCert(links);
      });
    }

    function downloadIssuerCert(links) {
      log('debug', 'Fetching issuer certificate: ' + links.up);
      return request(links.up).then(function(res) {
        state.chainPem = certBufferToPem(parseBody(res));
        log('debug', 'Successfully fetched issuer certificate');
      }).catch(function(error) {
        log('debug', 'Failed to fetch issuer certificate');
        throw error;
      });
    }
  };
};

function parseBody(res) {
  var error;

  if (!res.success) {
    error = new Error("Request failed with status code: " + res.status);
    error.code = "E_STATUS_CODE";
    throw error;
  }

  var body = res.data;
  if (!body) {
    error = new Error("Missing request body");
    error.code = "E_NO_RESPONSE_BODY";
    throw error;
  }

  if (body.slice(0, 1).toString() === '{') {
    try {
      body = JSON.parse(body.toString());
    } catch(e) {
      error = new Error("Failed to parse body");
      error.code = "E_BODY_PARSE";
      error.description = body;
      throw error;
    }
  }

  return body;
}

function certBufferToPem(cert) {
  assertValid(cert, 'buffer');
  cert = _toStandardBase64(cert.toString('base64'));
  cert = cert.match(/.{1,64}/g).join('\r\n');
  return '-----BEGIN CERTIFICATE-----\r\n' + cert + '\r\n-----END CERTIFICATE-----\r\n';
}

function _toStandardBase64(str) {
  var b64 = str.replace(/-/g, "+").replace(/_/g, "/").replace(/=/g, "");

  switch (b64.length % 4) {
    case 2: b64 += "=="; break;
    case 3: b64 += "="; break;
  }

  return b64;
}
