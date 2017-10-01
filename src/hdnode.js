var Buffer = require('safe-buffer').Buffer
var base58check = require('bs58check')
var bcrypto = require('./crypto')
var createHmac = require('create-hmac')
var typeforce = require('typeforce')
var types = require('./types')
var NETWORKS = require('./networks')

var ecc = require('./ecc')
var ecdsa = require('./ecsda')

function HDNode (d, Q, chainCode, network) {
  if (!(d ^ Q)) throw new TypeError('Only provide one')
  if (d) typeforce(ecc.types.UInt256, d)
  if (Q) typeforce(ecc.types.ECPointCompressed, Q)

  this.d = d || null
  this.Q = Q || ecc.pointDerive(d, true)
  this.chainCode = chainCode
  this.depth = 0
  this.index = 0
  this.parentFingerprint = 0x00000000
}

function fromSeed (seed, network) {
  typeforce(types.Buffer, seed)
  if (network) typeforce(types.Network, network)
  if (seed.length < 16) throw new TypeError('Seed should be at least 128 bits')
  if (seed.length > 64) throw new TypeError('Seed should be at most 512 bits')

  var I = createHmac('sha512', 'Bitcoin seed').update(seed).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  // In case IL is 0 or >= n, the master key is invalid
  // This is handled by the ECPair constructor
  if (!types.UInt256(IL)) throw new Error('Private key not in range [1, n)')

  return new HDNode(IL, null, IR, network)
}

function fromBase58 (string, networks) {
  var buffer = base58check.decode(string)
  if (buffer.length !== 78) throw new Error('Invalid buffer length')

  // 4 bytes: version bytes
  var version = buffer.readUInt32BE(0)
  var network

  // list of networks?
  if (Array.isArray(networks)) {
    network = networks.filter(function (x) {
      return version === x.bip32.private ||
             version === x.bip32.public
    }).pop()

    if (!network) throw new Error('Unknown network version')

  // otherwise, assume a network object (or default to bitcoin)
  } else {
    network = networks || NETWORKS.bitcoin
  }

  if (version !== network.bip32.private &&
    version !== network.bip32.public) throw new Error('Invalid network version')

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
  var depth = buffer[4]

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  var parentFingerprint = buffer.readUInt32BE(5)
  if (depth === 0) {
    if (parentFingerprint !== 0x00000000) throw new Error('Invalid parent fingerprint')
  }

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in MSB order. (0x00000000 if master key)
  var index = buffer.readUInt32BE(9)
  if (depth === 0 && index !== 0) throw new Error('Invalid index')

  // 32 bytes: the chain code
  var chainCode = buffer.slice(13, 45)
  var hd

  // 33 bytes: private key data (0x00 + k)
  if (version === network.bip32.private) {
    if (buffer.readUInt8(45) !== 0x00) throw new Error('Invalid private key')

    var d = buffer.slice(46, 78)
    hd = new HDNode(d, null, chainCode, network)

  // 33 bytes: public key data (0x02 + X or 0x03 + X)
  } else {
    var Q = buffer.slice(45, 78)
    hd = new HDNode(null, Q, chainCode, network)

    // verify that the X coordinate in the public point corresponds to a point on the curve.
    // If not, the extended public key is invalid.
    ecc.pointVerify(Q)
  }

  hd.depth = depth
  hd.index = index
  hd.parentFingerprint = parentFingerprint
  return hd
}

HDNode.prototype.getIdentifier = function () {
  return bcrypto.hash160(this.Q)
}

HDNode.prototype.getFingerprint = function () {
  return this.getIdentifier().slice(0, 4)
}

HDNode.prototype.getNetwork = function () {
  return this.network
}

HDNode.prototype.getPublicKeyBuffer = function () {
  return this.Q
}

HDNode.prototype.neutered = function () {
  var neutered = new HDNode(null, this.Q, this.chainCode)
  neutered.depth = this.depth
  neutered.index = this.index
  neutered.parentFingerprint = this.parentFingerprint

  return neutered
}

HDNode.prototype.toBase58 = function (__isPrivate) {
  if (__isPrivate !== undefined) throw new TypeError('Unsupported argument in 2.0.0')

  // Version
  var network = this.network
  var version = (!this.isNeutered()) ? network.bip32.private : network.bip32.public
  var buffer = Buffer.allocUnsafe(78)

  // 4 bytes: version bytes
  buffer.writeUInt32BE(version, 0)

  // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
  buffer.writeUInt8(this.depth, 4)

  // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
  buffer.writeUInt32BE(this.parentFingerprint, 5)

  // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
  // This is encoded in big endian. (0x00000000 if master key)
  buffer.writeUInt32BE(this.index, 9)

  // 32 bytes: the chain code
  this.chainCode.copy(buffer, 13)

  // 33 bytes: the public key or private key data
  if (!this.isNeutered()) {
    // 0x00 + k for private keys
    buffer.writeUInt8(0, 45)
    this.d.copy(buffer, 46)

  // 33 bytes: the public key
  } else {
    // X9.62 encoding for public keys
    this.Q.copy(buffer, 45)
  }

  return base58check.encode(buffer)
}

HDNode.prototype.sign = function (hash) {
  return ecdsa.sign(hash, this.d)
}

HDNode.prototype.verify = function (hash, signature) {
  return ecdsa.verify(hash, signature, this.Q)
}

var HIGHEST_BIT = 0x80000000

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions
HDNode.prototype.derive = function (index) {
  typeforce(types.UInt32, index)

  var isHardened = index >= HIGHEST_BIT
  var data = Buffer.allocUnsafe(37)

  // Hardened child
  if (isHardened) {
    if (this.isNeutered()) throw new TypeError('Could not derive hardened child key')

    // data = 0x00 || ser256(kpar) || ser32(index)
    data[0] = 0x00
    this.d.copy(data, 1)
    data.writeUInt32BE(index, 33)

  // Normal child
  } else {
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    this.Q.copy(data, 0)
    data.writeUInt32BE(index, 33)
  }

  var I = createHmac('sha512', this.chainCode).update(data).digest()
  var IL = I.slice(0, 32)
  var IR = I.slice(32)

  // In case parse256(IL) >= n, proceed with the next value for i
  if (!ecc.types.UInt256(IL)) return this.derive(index + 1)

  // Private parent key -> private child key
  var hd
  if (!this.isNeutered()) {
    // ki = parse256(IL) + kpar (mod n)
    var ki = ecc.intAdd(IL, this.d)

    // In case ki == 0, proceed with the next value for i
    if (!ecc.types.UInt256(ki)) return this.derive(index + 1)

    hd = new HDNode(ki, null, IR, this.network)

  // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    var Ki = ecc.pointAdd(ecc.pointDerive(IL), this.Q)

    // In case Ki is the point at infinity, proceed with the next value for i
    if (ecc.pointIsInfinity(Ki)) return this.derive(index + 1)

    hd = new HDNode(null, Ki, this.network)
  }

  hd.depth = this.depth + 1
  hd.index = index
  hd.parentFingerprint = this.getFingerprint().readUInt32BE(0)
  return hd
}

HDNode.prototype.deriveHardened = function (index) {
  typeforce(types.UInt31, index)

  // Only derives hardened private keys by default
  return this.derive(index + HIGHEST_BIT)
}

// Private === not neutered
// Public === neutered
HDNode.prototype.isNeutered = function () {
  return this.d === null
}

function BIP32Path (value) {
  return typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/)
}

HDNode.prototype.derivePath = function (path) {
  typeforce(BIP32Path, path)

  var splitPath = path.split('/')
  if (splitPath[0] === 'm') {
    if (this.parentFingerprint) throw new Error('Expected master node, got child node')

    splitPath = splitPath.slice(1)
  }

  return splitPath.reduce(function (prevHd, indexStr) {
    var index
    if (indexStr.slice(-1) === "'") {
      index = parseInt(indexStr.slice(0, -1), 10)
      return prevHd.deriveHardened(index)
    } else {
      index = parseInt(indexStr, 10)
      return prevHd.derive(index)
    }
  }, this)
}

module.exports = {
  fromBase58,
  fromSeed
}
