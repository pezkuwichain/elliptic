/* eslint-env node, mocha */
'use strict';

// Deterministic ECDSA signatures checked against an independent
// implementation (@noble/curves). The RFC 6979 nonce is also derived here
// with node's own HMAC so the cases where the DRBG output T starts with a zero
// byte (GHSA-848j-6mx2-7j84) are selected on purpose, not left to chance.

var assert = require('assert');
var crypto = require('crypto');
var BN = require('bn.js');
var nist = require('@noble/curves/nist');
var secp = require('@noble/curves/secp256k1');

var elliptic = require('../');

var RANDOM_CASES = 64;
var LEADING_ZERO_CASES = 16;

var curves = [
  { name: 'secp256k1', hash: 'sha256', noble: secp.secp256k1 },
  { name: 'p256', hash: 'sha256', noble: nist.p256 },
  { name: 'p384', hash: 'sha384', noble: nist.p384 },
  { name: 'p521', hash: 'sha512', noble: nist.p521 },
];

function hmac(alg, key, parts) {
  var h = crypto.createHmac(alg, key);
  parts.forEach(function(p) {
    h.update(p);
  });
  return h.digest();
}

// First RFC 6979 3.2 candidate T (step h), rlen bytes long.
function rfc6979FirstT(alg, n, priv, digest) {
  var rlen = n.byteLength();
  var qlen = n.bitLength();
  var x = Buffer.from(priv.toArray('be', rlen));
  var z = new BN(digest);
  var zbits = digest.length * 8;
  if (zbits > qlen)
    z = z.ushrn(zbits - qlen);
  var h1 = Buffer.from(z.umod(n).toArray('be', rlen));

  var hlen = crypto.createHash(alg).digest().length;
  var v = Buffer.alloc(hlen, 1);
  var k = Buffer.alloc(hlen, 0);
  k = hmac(alg, k, [ v, Buffer.from([ 0 ]), x, h1 ]);
  v = hmac(alg, k, [ v ]);
  k = hmac(alg, k, [ v, Buffer.from([ 1 ]), x, h1 ]);
  v = hmac(alg, k, [ v ]);

  var t = Buffer.alloc(0);
  while (t.length < rlen) {
    v = hmac(alg, k, [ v ]);
    t = Buffer.concat([ t, v ]);
  }
  return t.slice(0, rlen);
}

// Reproducible byte stream so a failure can be replayed.
function stream(label) {
  var counter = 0;
  return function(len) {
    var out = Buffer.alloc(0);
    while (out.length < len) {
      out = Buffer.concat([ out, crypto.createHash('sha512')
        .update(label + ':' + counter++).digest() ]);
    }
    return out.slice(0, len);
  };
}

function privateKey(n, bytes) {
  // 1 <= d <= n - 1
  return new BN(bytes(n.byteLength() + 16)).umod(n.subn(1)).addn(1);
}

function toHex(bn, len) {
  return bn.toString(16, len * 2);
}

function compare(c, ec, priv, digest) {
  var len = ec.n.byteLength();
  var privBytes = Uint8Array.from(priv.toArray('be', len));
  var key = ec.keyFromPrivate(priv);

  [ false, true ].forEach(function(lowS) {
    var mine = key.sign(Array.from(digest), { canonical: lowS });
    var ref = c.noble.sign(Uint8Array.from(digest), privBytes,
      { lowS: lowS, prehash: false });

    assert.strictEqual(toHex(mine.r, len), toHex(new BN(ref.r.toString(16), 16), len),
      c.name + ' r differs (lowS=' + lowS + ')');
    assert.strictEqual(toHex(mine.s, len), toHex(new BN(ref.s.toString(16), 16), len),
      c.name + ' s differs (lowS=' + lowS + ')');
    assert.strictEqual(mine.recoveryParam, ref.recovery,
      c.name + ' recovery differs (lowS=' + lowS + ')');
    assert(ec.verify(Array.from(digest), mine, key.getPublic()));
  });
}

describe('RFC 6979 signatures match @noble/curves', function() {
  this.timeout(10 * 60 * 1000);

  curves.forEach(function(c) {
    describe('curve ' + c.name, function() {
      var ec = new elliptic.ec(c.name);

      it('agrees on ' + RANDOM_CASES + ' random keys and digests', function() {
        var bytes = stream('random/' + c.name);
        for (var i = 0; i < RANDOM_CASES; i++) {
          var priv = privateKey(ec.n, bytes);
          var digest = crypto.createHash(c.hash).update(bytes(32)).digest();
          compare(c, ec, priv, digest);
        }
      });

      it('agrees on ' + LEADING_ZERO_CASES +
         ' cases whose nonce candidate starts with a zero byte', function() {
        var bytes = stream('leading-zero/' + c.name);
        var found = 0;
        var tried = 0;
        while (found < LEADING_ZERO_CASES) {
          assert(tried++ < LEADING_ZERO_CASES * 256 * 20,
            'no leading zero nonce found');
          var priv = privateKey(ec.n, bytes);
          var digest = crypto.createHash(c.hash).update(bytes(32)).digest();
          if (rfc6979FirstT(c.hash, ec.n, priv, digest)[0] !== 0)
            continue;
          compare(c, ec, priv, digest);
          found++;
        }
      });
    });
  });
});
