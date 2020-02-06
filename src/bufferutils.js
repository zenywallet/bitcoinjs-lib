// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint (value, max) {
  if (typeof value !== 'number') throw new Error('cannot write a non-number as a number')
  if (value < 0) throw new Error('specified a negative value for writing an unsigned value')
  if (value > max) throw new Error('RangeError: value out of range')
  if (Math.floor(value) !== value) throw new Error('value has a fractional component')
}

function readUInt64LE (buffer, offset) {
  const a = buffer.readUInt32LE(offset)
  let b = buffer.readUInt32LE(offset + 4)
  b *= 0x100000000

  verifuint(b + a, 0x001fffffffffffff)
  return b + a
}

function writeUInt64LE (buffer, value, offset) {
  if(value instanceof UINT64) {
    buffer.writeUInt16LE(value._a00, offset)
    buffer.writeUInt16LE(value._a16, offset + 2)
    buffer.writeUInt16LE(value._a32, offset + 4)
    buffer.writeUInt16LE(value._a48, offset + 6)
    return offset + 8
  }
  verifuint(value, 0x001fffffffffffff)

  buffer.writeInt32LE(value & -1, offset)
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4)
  return offset + 8
}

module.exports = {
  readUInt64LE: readUInt64LE,
  writeUInt64LE: writeUInt64LE
}
