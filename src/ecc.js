let bn = require('bn.js')
let secp256k1 = require('node-secp256k1')

function intAdd (a, b) {
  var A = bn.fromBuffer(a)
  var B = bn.fromBuffer(b)

  return A.add(B).toBuffer(32)
}

function intCheck (a) {
  var A = bn.fromBuffer(a)

  return A.signum() > 0 && A.compareTo(secp256k1.n) < 0
}

function intSign (a) {
  return bn.fromBuffer(a).signum()
}

function pointAdd (p, q) {
  var P = secp256k1.Point.decodeFrom(p)
  var Q = secp256k1.Point.decodeFrom(q)
  var R = P.add(Q)

  if (secp256k1.isInfinity(R)) return null
  return R.getEncoded(P.compressed)
}

function pointDerive (d, compressed) {
  return secp256k1.G.multiply(d).getEncoded(compressed)
}

function pointIsInfinity (q) {
  return secp256k1.isInfinity(q)
}

function pointVerify (q) {
  var Q = secp256k1.Point.decodeFrom(q)
  return secp256k1.validate(Q)
}

var EC_ZERO = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var EC_UINT_MAX = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')

function UInt256 (value) {
  return Buffer.isBuffer(value) &&
    value.length === 32 &&
    value.compare(EC_ZERO) > 0 && // > 0
    value.compare(EC_UINT_MAX) < 0 // < n-1
}

function ECPoint (value) {
  if (!Buffer.isBuffer(value)) return false
  if (value.length < 33) return false

  switch (value[0]) {
    case 0x02:
    case 0x03:
      return value.length === 33
    case 0x04:
      return value.length === 65
  }

  return false
}

function ECPointCompressed (value) {
  return ECPoint(value) && value.length === 33
}

//  var ECSignature = typeforce.compile({ r: BigInt, s: BigInt })

module.exports = {
  intAdd: intAdd,
  intCheck: intCheck,
  intSign: intSign,
  pointAdd: pointAdd,
  pointDerive: pointDerive,
  pointIsInfinity: pointIsInfinity,
  pointVerify: pointVerify,
  types: {
    UInt256,
    ECPoint,
    ECPointCompressed
  }
}
