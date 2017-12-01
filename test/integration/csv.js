/* global describe, it */

var assert = require('assert')
var bitcoin = require('../../')
var testnetUtils = require('./_testnet')

var testnet = bitcoin.networks.testnet
var alice = bitcoin.ECPair.fromWIF('cScfkGjbzzoeewVWmU2hYPUHeVGJRDdFt7WhmrVVGkxpmPP8BHWe', testnet)
var bob = bitcoin.ECPair.fromWIF('cMkopUXKWsEzAjfa1zApksGRwjVpJRB3831qM9W4gKZsLwjHXA9x', testnet)

describe('bitcoinjs-lib (transactions w/ CSV)', function () {
  var hashType = bitcoin.Transaction.SIGHASH_ALL

  // IF MTP > utcSeconds, aQ can redeem, ELSE bQ, aQ joint redeem
  function cltvCheckSigOutput (aQ, bQ, utcSeconds) {
    return bitcoin.script.compile([
      [height] CSV DROP DUP HASH160 [hash] EQUALVERIFY CHECKSIG

      bitcoin.opcodes.OP_IF,
      bitcoin.script.number.encode(utcSeconds),
      bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
      bitcoin.opcodes.OP_DROP,

      bitcoin.opcodes.OP_ELSE,
      bQ.getPublicKeyBuffer(),
      bitcoin.opcodes.OP_CHECKSIGVERIFY,
      bitcoin.opcodes.OP_ENDIF,

      aQ.getPublicKeyBuffer(),
      bitcoin.opcodes.OP_CHECKSIG
    ])
  }

  function utcNow () {
    return Math.floor(Date.now() / 1000)
  }

  // expiry past, {Alice's signature} OP_TRUE
  it('can create (and broadcast via 3PBP) a Transaction where Alice can redeem the output after the expiry', function (done) {
    this.timeout(30000)

    // three hours ago
    var timeUtc = utcNow() - (3600 * 3)
    var redeemScript = cltvCheckSigOutput(alice, bob, timeUtc)
    var scriptPubKey = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(redeemScript))
    var address = bitcoin.address.fromOutputScript(scriptPubKey, testnet)

    // fund the P2SH(CLTV) address
    testnetUtils.faucet(address, 2e4, function (err, unspent) {
      if (err) return done(err)

      var tx = new bitcoin.TransactionBuilder(testnet)
      tx.setLockTime(timeUtc)
      tx.addInput(unspent.txId, 0, 0xfffffffe)
      tx.addOutput(testnetUtils.RETURN_ADDRESS, 1e4)

      var txRaw = tx.buildIncomplete()
      var signatureHash = txRaw.hashForSignature(0, redeemScript, hashType)

      // {Alice's signature} OP_TRUE
      var redeemScriptSig = bitcoin.script.scriptHash.input.encode([
        alice.sign(signatureHash).toScriptSignature(hashType),
        bitcoin.opcodes.OP_TRUE
      ], redeemScript)

      txRaw.setInputScript(0, redeemScriptSig)

      testnetUtils.transactions.propagate(txRaw.toHex(), done)
    })
  })
})
