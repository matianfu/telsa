// K combinator
const K = x => y => x

// returns buffer
const UInt8 = i => Buffer.from([i])
const UInt16 = i => Buffer.from([i >> 8, i])
const UInt24 = i => Buffer.from([i >> 16, i >> 8, i])

// read (peek) 
const readUInt24 = buf => buf[0] * 65536 + buf[1] * 256 + buf[2]

// prepend length to given buffer
const Prepend8 = b => Buffer.concat([UInt8(b.length), b])
const Prepend16 = b => Buffer.concat([UInt16(b.length), b])
const Prepend24 = b => Buffer.concat([UInt24(b.length), b])


const TLSVersion = Buffer.from([0x03, 0x03])
const AES_128_CBC_SHA = Buffer.from([0x00, 0x2f])

module.exports = {
  K,
  UInt8,
  UInt16,
  UInt24,
  readUInt24,
  Prepend8,
  Prepend16,
  Prepend24,

  TLSVersion,
  AES_128_CBC_SHA
}

