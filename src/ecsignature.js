var bip66 = require('bip66')

function fromDER (buffer) {
  return bip66.decode(buffer)
}

function toDER (rBuffer, sBuffer) {
  return bip66.encode(rBuffer, sBuffer)
}

// BIP62: 1 byte hashType flag (only 0x01, 0x02, 0x03, 0x81, 0x82 and 0x83 are allowed)
function fromScriptSignature (buffer) {
  var hashType = buffer.readUInt8(buffer.length - 1)
  var hashTypeMod = hashType & ~0x80

  if (hashTypeMod <= 0x00 || hashTypeMod >= 0x04) throw new Error('Invalid hashType ' + hashType)

  var decode = fromDER(buffer.slice(0, -1))
  decode.hashType = hashType
  return decode
}

function toScriptSignature (signature, hashType) {
  var hashTypeMod = hashType & ~0x80
  if (hashTypeMod <= 0 || hashTypeMod >= 4) throw new Error('Invalid hashType ' + hashType)

  var hashTypeBuffer = Buffer.alloc(1)
  hashTypeBuffer.writeUInt8(hashType, 0)

  return Buffer.concat([toDER(signature), hashTypeBuffer])
}

module.exports = {
  fromDER,
  toDER,
  fromScriptSignature,
  toScriptSignature
}
