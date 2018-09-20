const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')

// 
const PRF = require('./prf')

// constants
const { RSA_PKCS1_PADDING } = crypto.constants

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

const HandshakeMessage = (type, msg) =>
  Buffer.concat([UInt8(type), UInt24(msg.length), msg])

const ClientHello = random =>
  HandshakeMessage(1, Buffer.concat([
    TLSVersion,
    random,
    Buffer.from([0]), // session_id
    Buffer.from([0x00, 0x02, 0x00, 0x2f]), // cipher_suites
    Buffer.from([0x01, 0x00]), // compression_methods
    Buffer.from([
      0x00, 0x0a, // Extensions Length: 10
      0x00, 0x0d, // type: signature_algorithms
      0x00, 0x06, // length: 6
      0x00, 0x04, // Signature Hash Algorithms Length: 4
      0x04, 0x01, // sha256, rsa
      0x02, 0x01 // sha1, rsa
    ])
  ]))

const handleServerHello = msg => {
  const unshift = size => K(msg.slice(0, size))(msg = msg.slice(size))
  if (!unshift(2).equals(TLSVersion)) throw new Error('unsupported tls version')
  let random = unshift(32)
  let sessionId = unshift(unshift(1)[0])
  if (!unshift(2).equals(AES_128_CBC_SHA)) throw new Error('unsupported cipher suite')
  if (unshift(1)[0] !== 0) throw new Error('unsupported compression')
  if (msg.length !== 0) console.log('WARNING: extra data in server hello message')
  return { random, sessionId }
}

const handleServerCertificate = msg  => {
  const unshift = size => K(msg.slice(0, size))(msg = msg.slice(size))
  if (msg.length < 3 || readUInt24(unshift(3)) !== msg.length) 
    throw new Error('invalid message length')

  let certs = []
  while (msg.length) {
    if (msg.length < 3 || readUInt24(msg) + 3 > msg.length) 
      throw new Error('invalid cert length')
    certs.push(unshift(readUInt24(unshift(3))))
  }

  let input = certs[0]
  let publicKey = child.execSync('openssl x509 -inform der -noout -pubkey', { input })
  return { publicKey, certs }
}

const handleCertificateRequest = msg => {
  const unshift = size => K(msg.slice(0, size))(msg = msg.slice(size))

  if (msg.length < 1 || msg[0] + 1 > msg.length) throw new Error('invalid length')
  let certTypes = Array.from(unshift(unshift(1)[0]))  
  
  if (msg.length < 2 || msg.readUInt16BE() % 2 || msg.readUInt16BE() + 2 > msg.length) 
    throw new Error('invalid length')

  let sigAlgorithms = Array.from(unshift(unshift(2).readUInt16BE()))
    .reduce((acc, c, i, arr) => (i % 2) ? [...acc, arr[i - 1] * 256 + c] : acc, [])

  // distinguished names are omitted
  return { certTypes, sigAlgorithms }
}

const handleServerHelloDone = msg => {
  if (msg.length) throw new Error('server hello done not empty')
}

const ClientCertificate = certs => HandshakeMessage(0x0b, 
  Prepend24(Buffer.concat([...certs.map(c => Prepend24(c))])))

const ClientKeyExchange = (key, preMasterSecret) => HandshakeMessage(0x10, 
  Prepend16(crypto.publicEncrypt({ key, padding: RSA_PKCS1_PADDING }, preMasterSecret)))

const CertificateVerify = (key, tbs) => HandshakeMessage(0x0f, 
  Buffer.concat([Buffer.from([0x04, 0x01]), // algorithm
    Prepend16(crypto.createSign('sha256').update(tbs).sign(key)) ]))

// when generating master secret, client random first
// when deriving keys, server random first
const deriveKeys = (preMasterSecret, clientRandom, serverRandom) => {
  let random = Buffer.concat([clientRandom, serverRandom])
  masterSecret = PRF(preMasterSecret, 'master secret', random, 48, 'sha256')
  random = Buffer.concat([serverRandom, clientRandom])
  let keys = PRF(masterSecret, 'key expansion', random, 2 * (20 + 16), 'sha256')
  return {
    masterSecret,
    clientWriteMacKey: keys.slice(0, 20),
    serverWriteMacKey: keys.slice(20, 40),
    clientWriteKey: keys.slice(40, 56),
    serverWriteKey: keys.slice(56, 72)
  }
}

const ClientFinished = (masterSecret, digest) => 
  HandshakeMessage(0x14, PRF(masterSecret, 'client finished', digest, 12, 'sha256'))

const Cipher = (plain, macKey, key, iv) => {
  let sn = Buffer.alloc(8)
  let mac = crypto.createHmac('sha1', macKey)
    .update(Buffer.concat([sn, UInt8(22), TLSVersion, UInt16(plain.length), plain]))
    .digest()

  let padding = 16 - ((plain.length + mac.length) % 16)
  let fragment = Buffer.concat([plain, mac, Buffer.alloc(padding, padding - 1)])
  let cipher = crypto.createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
  return Buffer.concat([iv, cipher.update(fragment), cipher.final()])
}

const Decipher = (encrypted, macKey, key, sn) => {
  // decipher
  let decipher = crypto
    .createDecipheriv('aes-128-cbc', key, encrypted.slice(0, 16))
    .setAutoPadding(false)
  let padded = Buffer.concat([decipher.update(encrypted.slice(16)), decipher.final()])

  // unpad
  let padNum = padded[padded.length - 1] + 1
  if (padded.length < padNum) throw new Error('invalid padding')
  if (!padded.slice(padded.length - padNum).equals(Buffer.alloc(padNum, padNum - 1)))
    throw new Error('invalid padding')

  // dec + mac + pad = padded
  let dec = padded.slice(0, padded.length - padNum - 20)
  let smac = padded.slice(padded.length - padNum - 20, padded.length - padNum)
  let cmac = crypto.createHmac('sha1', macKey)
    .update(Buffer.concat([sn, UInt8(22), TLSVersion, UInt16(dec.length), dec]))
    .digest()

  // compare mac
  if (!smac.equals(cmac)) throw new Error('mac mismatch')
  return dec
}

const handleServerFinished = (msg, masterSecret, digest) => {
  if (msg.length < 4) throw new Error('invalid message length')
  if (msg[0] !== 20) throw new Error('not a finished message')

  let length = msg.readUInt32BE(0) & 0x00ffffff
  let body = msg.slice(4)
  if (length !== body.length) throw new Error('invalid message body length')
  if (length !== 12) throw new Error('verify data length mismatch')
  let verifyData = PRF(masterSecret, 'server finished', digest, 12, 'sha256')
  if (!verifyData.equals(body)) throw new Error('verify data mismatch')
}

module.exports = {
  ClientHello,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest,
  handleServerHelloDone,
  ClientCertificate,
  ClientKeyExchange,
  CertificateVerify,
  ClientFinished,
  deriveKeys,
  Cipher,
  Decipher,
  handleServerFinished
}
