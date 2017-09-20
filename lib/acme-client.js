/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/
'use strict';

var assertValid = require('assertValid');
var request = require('request');
var RSA = require('rsa-compat').RSA;

var generateSignature = RSA.signJws;

var configTypes = {
  keyPair: 'string|object',
  log: 'function?',
};

function Acme(config) {
  assertValid(config, configTypes);
  if (typeof config.keyPair === 'string') {
    // backwards compat
    this.keyPair = RSA.import({
      privateKeyPem: config.keyPair
    });
  } else {
    this.keyPair = config.keyPair;
  }
  this.nonces = [];
  this._log = config.log || Function.prototype;
}

Acme.prototype.getNonce = function(url) {
  var self = this;
  return request(url, {
    method: 'HEAD',
  }).then(function(res) {
    var nonce = res.headers['replay-nonce'];
    if (nonce) {
      self._log('verbose', 'Storing nonce: ' + nonce);
      self.nonces.push(nonce);
    } else {
      throw Error('Failed to get nonce for request');
    }
  });
};

function signedPayload(json, keyPair, nonce) {
  payload = generateSignature(keyPair, new Buffer(json), nonce);
  return JSON.stringify(payload, null, 2);
}

Acme.prototype.post = function(url, body) {
  var self = this;

  if (!self.nonces.length) {
    return self.getNonce(url).then(function() {
      return self.post(url, body);
    });
  }

  self._log('debug', 'Posting to: ' + url);

  var nonce = self.nonce.shift();
  self._log('debug', 'Using nonce: ' + nonce);

  var payload = JSON.stringify(body, null, 2);
  self._log('debug', 'Payload: ' + payload);

  payload = signedPayload(payload, self.keyPair, nonce);
  self._log('debug', 'Signed: ' + payload);

  // process.exit(1);
  // return;
  return request(url, {
    data: payload,
  }).then(function(res) {
    self._log('debug', 'Status: ' + res.status);
    self._log('debug', 'Headers: ' + JSON.stringify(res.headers, null, 2));

    var json;
    try {
      json = res.json;
      self._log('debug', JSON.stringify(json, null, 2));
    } catch(error) {
      self._log('debug', res.text);
    }

    var nonce = res.headers['replay-nonce'];
    if (nonce) {
      self._log('verbose', 'Storing nonce: ' + nonce);
      self.nonces.push(nonce);
    }

    return res;
  });
};

Acme.parseLink = function(link) {
  try {
    return link.split(',').map(function(link) {
      var parts = link.trim().split(';');
      var url = parts.shift().replace(/[<>]/g, '');
      var info = parts.reduce(function(acc, p) {
        var m = p.trim().match(/(.+) *= *"(.+)"/);
        if (m) {
          acc[m[1]] = m[2];
        }
        return acc;
      }, {});
      info.url = url;
      return info;
    }).reduce(function(acc, link) {
      if ('rel' in link) {
        acc[link.rel] = link.url;
      }
      return acc;
    }, {});
  } catch(err) {
    return null;
  }
};

module.exports = Acme;
