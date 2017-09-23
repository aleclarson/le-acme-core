/*!
 * le-acme-core
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var generateCsr = require('csr-gen');
var assertValid = require('assertValid');
var request = require('request');
var RSA = require('rsa-utils');

var Acme = require('./acme-client');

var optionTypes = {
  subject: generateCsr.subjectTypes,
  domains: 'array',
  domainKeyPair: 'object',
  accountKeyPair: 'object',
  newAuthzUrl: 'string',
  newCertUrl: 'string',
  challengeType: 'string?',
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

    try {
      var acme = new Acme({
        keyPair: options.accountKeyPair,
        log: log,
      });
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
      return {
        cert: certBufferToPem(state.certificate),
        key: RSA.exportPrivatePem(options.domainKeyPair),
        ca: state.chainPem,
      };
    });

    function nextDomain() {
      if (state.domains.length) {
        return getChallenges(state.domains.shift());
      } else {
        log('debug', 'Generating CSR...');
        return RSA.generateCsrDerWeb64(
          options.domainKeyPair,
          state.validatedDomains,
          options.subject
        ).then(function(csr) {
          log('debug', 'Fetching new certificate: ' + state.newCertUrl);
          return acme.post(state.newCertUrl, {
            resource: 'new-cert',
            csr: csr.toString(),
            authorizations: state.validAuthorizationUrls,
          }).then(downloadCertificates, function(error) {
            log('debug', 'Failed to fetch new certificate');
            throw error;
          });
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
      var authz = parseBody(res);
      var challenges = authz.challenges.filter(function(x) {
        return x.type === options.challengeType;
      });
      if (challenges.length === 0) {
        throw Error("CA failed to return a challenge we can handle");
      }

      var links = Acme.parseLink(res.headers.link);
      if (!(links && 'next' in links)) {
        throw Error("CA failed to return the 'new-cert' url");
      }

      state.authorizationUrl = res.headers.location;
      state.newCertUrl = links.next;

      var challenge = challenges[0];
      var thumbprint = RSA.thumbprint(options.accountKeyPair);
      var keyAuthorization = challenge.token + '.' + thumbprint;
      var domain = state.domain;
      var token = challenge.token;

      return new Promise(function(resolve) {
        options.setChallenge(domain, token, keyAuthorization, resolve);
      }).then(function() {
        log('debug', 'Posting challenge: ' + challenge.uri);
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
        return new Promise(function(resolve) {
          options.removeChallenge(domain, token, resolve);
        }).then(function() {
          throw error;
        }).catch(function(error) {
          log('debug', '`options.removeChallenge` threw an error');
          throw error;
        });
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
        setImmediate(unlink);
        if (authz.challenges) {
          var challenge = authz.challenges.filter(function(challenge) {
            return challenge.type === options.challengeType;
          })[0] || authz;
          throw Error("CA validation failed: " + JSON.stringify(challenge, null, 2));
        } else {
          throw Error("CA validation failed: " + JSON.stringify(authz, null, 2));
        }

      default:
        setImmediate(unlink);
        throw Error(
          "CA returned an authorization in an unexpected state: " +
          JSON.stringify(authz, null, 2)
        );
      }
    }

    function downloadCertificates(res) {
      state.certificate = parseBody(res);

      var links = Acme.parseLink(res.headers.link);
      if (!links || !('up' in links)) {
        throw Error("CA failed to return the 'ca-cert' url");
      }

      var certUrl = res.headers.location;
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
        log('debug', 'Fetching issuer certificate: ' + links.up);
        return request(links.up).then(function(res) {
          state.chainPem = certBufferToPem(parseBody(res));
        });
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
  cert = toStandardBase64(cert.toString('base64'));
  cert = cert.match(/.{1,64}/g).join('\r\n');
  return '-----BEGIN CERTIFICATE-----\r\n' + cert + '\r\n-----END CERTIFICATE-----\r\n';
}

function toStandardBase64(str) {
  var b64 = str.replace(/-/g, "+").replace(/_/g, "/").replace(/=/g, "");

  switch (b64.length % 4) {
    case 2: b64 += "=="; break;
    case 3: b64 += "="; break;
  }

  return b64;
}
