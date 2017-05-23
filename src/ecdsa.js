var createHmac = require('create-hmac')
var typeforce = require('typeforce')
var types = require('./types')

var BigInteger = require('bigi')
var ECSignature = require('./ecsignature')

var ZERO = new Buffer([0])
var ONE = new Buffer([1])

var ecurve = require('ecurve')
var secp256k1 = ecurve.getCurveByName('secp256k1')

// https://tools.ietf.org/html/rfc6979#section-3.2
function deterministicGenerateK (hash, x, checkSig) {
  typeforce(types.tuple(
    types.Hash256bit,
    types.Buffer256bit,
    types.Function
  ), arguments)

  var k = new Buffer(32)
  var v = new Buffer(32)

  // Step A, ignored as hash already provided
  // Step B
  v.fill(1)

  // Step C
  k.fill(0)

  // Step D
  k = createHmac('sha256', k)
    .update(v)
    .update(ZERO)
    .update(x)
    .update(hash)
    .digest()

  // Step E
  v = createHmac('sha256', k).update(v).digest()

  // Step F
  k = createHmac('sha256', k)
    .update(v)
    .update(ONE)
    .update(x)
    .update(hash)
    .digest()

  // Step G
  v = createHmac('sha256', k).update(v).digest()

  // Step H1/H2a, ignored as tlen === qlen (256 bit)
  // Step H2b
  v = createHmac('sha256', k).update(v).digest()

  var T = BigInteger.fromBuffer(v)

  // Step H3, repeat until T is within the interval [1, n - 1] and is suitable for ECDSA
  while (T.signum() <= 0 || T.compareTo(secp256k1.n) >= 0 || !checkSig(T)) {
    k = createHmac('sha256', k)
      .update(v)
      .update(ZERO)
      .digest()

    v = createHmac('sha256', k).update(v).digest()

    // Step H1/H2a, again, ignored as tlen === qlen (256 bit)
    // Step H2b again
    v = createHmac('sha256', k).update(v).digest()
    T = BigInteger.fromBuffer(v)
  }

  return T
}

var N_OVER_TWO = secp256k1.n.shiftRight(1)

function sign (hash, d) {
  typeforce(types.tuple(types.Hash256bit, types.BigInt), arguments)

  var x = d.toBuffer(32)
  var e = BigInteger.fromBuffer(hash)
  var n = secp256k1.n
  var G = secp256k1.G

  var r, s
  deterministicGenerateK(hash, x, function (k) {
    var Q = G.multiply(k)

    if (secp256k1.isInfinity(Q)) return false

    r = Q.affineX.mod(n)
    if (r.signum() === 0) return false

    s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n)
    if (s.signum() === 0) return false

    return true
  })

  // enforce low S values, see bip62: 'low s values in signatures'
  if (s.compareTo(N_OVER_TWO) > 0) {
    s = n.subtract(s)
  }

  return new ECSignature(r, s)
}

function verify (hash, signature, Q) {
  typeforce(types.tuple(
    types.Hash256bit,
    types.ECSignature,
    types.ECPoint
  ), arguments)

  var n = secp256k1.n
  var G = secp256k1.G

  var r = signature.r
  var s = signature.s

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1]
  if (r.signum() <= 0 || r.compareTo(n) >= 0) return false
  if (s.signum() <= 0 || s.compareTo(n) >= 0) return false

  // 1.4.2 H = Hash(M), already done by the user
  // 1.4.3 e = H
  var e = BigInteger.fromBuffer(hash)

  // Compute s^-1
  var sInv = s.modInverse(n)

  // 1.4.4 Compute u1 = es^−1 mod n
  //               u2 = rs^−1 mod n
  var u1 = e.multiply(sInv).mod(n)
  var u2 = r.multiply(sInv).mod(n)

  // 1.4.5 Compute R = (xR, yR)
  //               R = u1G + u2Q
  var R = G.multiplyTwo(u1, Q, u2)

  // 1.4.5 (cont.) Enforce R is not at infinity
  if (secp256k1.isInfinity(R)) return false

  var xr = r
  var pr = R
  var p = secp256k1.p
  var prz2 = pr.z.square().mod(p)

  /* xr * pr.z^2 mod p == pr.x, so the signature is valid. */
  if (xr.multiply(prz2).mod(p).equals(pr.x)) return true

  /* xr + n >= p, so we can skip testing the second case. */
  if (xr.compareTo(p.subtract(n)) >= 0) return false

  /* (xr + n) * pr.z^2 mod p == pr.x, so the signature is valid. */
  if (xr.add(n).multiply(prz2).mod(p).equals(pr.x)) return true

  return false
}

module.exports = {
  deterministicGenerateK: deterministicGenerateK,
  sign: sign,
  verify: verify,

  // TODO: remove
  __curve: secp256k1
}
