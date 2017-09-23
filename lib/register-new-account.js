/*!
 * le-acme-core
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
 */
'use strict';

var assertValid = require('assertValid');
var request = require('request');

var Acme = require('./acme-client');

var optionTypes = {
  agreeToTerms: 'function', // (tosUrl, done(true|false))
  accountKeyPair: 'string',
  newRegUrl: 'string',
  email: 'string',
};

exports.create = function(config) {
  var log = config.log;
  return function registerNewAccount(options) {
    assertValid(options, optionTypes);

    var acme;
    try {
      acme = new Acme(options.accountKeyPair);
    } catch(error) {
      throw Error("Failed to parse private key. " + error.message);
    }

    var state = {};
    return acme.post(options.newRegUrl, {
      resource: 'new-reg',
      contact: ['mailto:' + options.email],
    }).then(function(res) {
      if (!res.success) {
        throw Error("Request failed with status code: " + res.status);
      }

      var links = Acme.parseLink(res.headers.link);
      if (!links || !('next' in links)) {
        throw Error("CA failed to return the new authorization url");
      }

      // TODO: Should we pass this along?
      // state.newAuthorizationUrl = links.next;

      state.registrationUrl = res.headers.location;
      state.termsRequired = 'terms-of-service' in links;

      if (state.termsRequired) {
        state.termsUrl = links['terms-of-service'];
        return new Promise(function(resolve, reject) {
          options.agreeToTerms(state.termsUrl, function(agree) {
            if (!agree) {
              reject(Error("You must agree to the 'Terms of Use' at: " + state.termsUrl));
            } else {
              log('verbose', 'The \'Terms of Use\' were agreed to: ' + state.termsUrl);
              request(state.termsUrl).then(function(res) {
                var text = res.text;
                if (!res.success || !text) {
                  throw Error("Failed to fetch the agreement");
                }
                log('verbose', 'Posting agreement to: ' + state.registrationUrl);
                return acme.post(state.registrationUrl, {
                  resource: 'reg',
                  agreement: state.termsUrl,
                });
              }).then(function(res) {
                if (!res.success) {
                  throw Error("Failed to POST agreement back to server");
                }
                var body = res.data;
                if (body.slice(0, 1).toString() === '{') {
                  body = JSON.parse(body.toString());
                }
                resolve(body);
              }).catch(reject);
            }
          });
        });
      } else {
        return null;
      }
    }).catch(function(error) {
      log('debug', 'Registration request failed');
      throw error;
    });
  };
};
