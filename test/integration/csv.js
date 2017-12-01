/* global describe, it */

var assert = require('assert')
var bitcoin = require('../../')
var testnetUtils = require('./_testnet')
var bip68 = require('bip68')

var testnet = bitcoin.networks.testnet
var alice = bitcoin.ECPair.fromWIF('cScfkGjbzzoeewVWmU2hYPUHeVGJRDdFt7WhmrVVGkxpmPP8BHWe', testnet)

describe('bitcoinjs-lib (transactions w/ CSV)', function () {
  var hashType = bitcoin.Transaction.SIGHASH_ALL

  // IF MTP (from when confirmed) > seconds, aQ can redeem
  function p2pkhCSV (sequence) {
    return bitcoin.script.compile([
      bitcoin.script.number.encode(sequence),
      bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY,
      bitcoin.opcodes.OP_DROP,
      alice.getPublicKeyBuffer(),
      bitcoin.opcodes.OP_CHECKSIG
    ])
  }

  it('can create (and fail to broadcast via 3PBP) a Transaction where Alice wants to redeem, but must wait for an expiry', function (done) {
    this.timeout(30000)

    // 1 hour from now
    var sequence = bip68.encode({ seconds: 3600 })

    var redeemScript = p2pkhCSV(sequence)
    var scriptPubKey = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(redeemScript))
    var address = bitcoin.address.fromOutputScript(scriptPubKey, testnet)

    // fund the P2SH(CLTV) address
    testnetUtils.faucet(address, 2e4, function (err, unspent) {
      if (err) return done(err)

      var tx = new bitcoin.TransactionBuilder(testnet)
      tx.addInput(unspent.txId, 0, sequence)
      tx.addOutput(testnetUtils.RETURN_ADDRESS, 1e4)

      var txRaw = tx.buildIncomplete()
      var signatureHash = txRaw.hashForSignature(0, redeemScript, hashType)

      // {Alice's signature}
      var redeemScriptSig = bitcoin.script.scriptHash.input.encode([
        alice.sign(signatureHash).toScriptSignature(hashType)
      ], redeemScript)

      txRaw.setInputScript(0, redeemScriptSig)

      // TODO: fix
      testnetUtils.transactions.propagate(txRaw.toHex(), done)
    })
  })
})
