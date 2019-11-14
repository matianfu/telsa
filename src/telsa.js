const child = require('child_process')
const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')
const {
  createHash, createHmac, createSign, createCipheriv,
  createDecipheriv, publicEncrypt, randomFillSync
} = crypto

const { concat, from } = Buffer
const debug = require('debug')

const logI = debug('telsa:info')

/**
 * content type for TLS record layer
 * @readonly
 * @enum {number}
 */
const ContentType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
}

/**
 * handshake record type
 * @readonly
 * @enum {number} - 1 byte
 */
const HandshakeType = {
  HELLO_REQUEST: 0,
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_HELLO_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20
}

/**
 * @param {number} handshake message type
 * @returns {string} handshake message name
 */
const handshakeTypeName = type => {
  switch (type) {
    case HandshakeType.HELLO_REQUEST:
      return 'HelloRequest'
    case HandshakeType.CLIENT_HELLO:
      return 'ClientHello'
    case HandshakeType.SERVER_HELLO:
      return 'ServerHello'
    case HandshakeType.CERTIFICATE:
      return 'Certificate'
    case HandshakeType.SERVER_KEY_EXCHANGE:
      return 'ServerKeyExchange'
    case HandshakeType.CERTIFICATE_REQUEST:
      return 'CertificateRequest'
    case HandshakeType.SERVER_HELLO_DONE:
      return 'ServerHelloDone'
    case HandshakeType.CERTIFICATE_VERIFY:
      return 'CertificateVerify'
    case HandshakeType.CLIENT_KEY_EXCHANGE:
      return 'ClientKeyExchange'
    case HandshakeType.FINISHED:
      return 'Finished'
    default:
      throw new Error(`unknown type ${type}`)
  }
}

/**
 * alert description (warning or error)
 * @readonly
 * @enum {number} - 1 byte
 */
const AlertDescription = {
  CLOSE_NOTIFY: 0,
  UNEXPECTED_MESSAGE: 10,
  BAD_RECORD_MAC: 20,
  DECRYPTION_FAILED_RESERVED: 21,
  RECORD_OVERFLOW: 22,
  DECOMPRESSION_FAILURE: 30,
  HANDSHAKE_FAILURE: 40,
  NO_CERTIFICATE_RESERVED: 41,
  BAD_CERTIFICATE: 42,
  UNSUPPORTED_CERTIFICATE: 43,
  CERTIFICATE_REVOKED: 44,
  CERTIFICATE_EXPIRED: 45,
  CERTIFICATE_UNKNOWN: 46,
  ILLEGAL_PARAMETER: 47,
  UNKNOWN_CA: 48,
  ACCESS_DENIED: 49,
  DECODE_ERROR: 50,
  DECRYPT_ERROR: 51,
  EXPORT_RESTRICTION_RESERVED: 60,
  PROTOCOL_VERSION: 70,
  INSUFFICIENT_SECURITY: 71,
  INTERNAL_ERROR: 80,
  USER_CANCELED: 90,
  NO_RENEGOTIATION: 100,
  UNSUPPORTED_EXTENSION: 110
}

const CloseNotify = from([1, AlertDescription.CLOSE_NOTIFY])
const InternalError = from([2, AlertDescription.INTERNAL_ERROR])

/** @function */
const K = x => y => x
/** @constant {buffer} - TLS version 1.2 */
const VER12 = from([0x03, 0x03])
/** @constant {buffer} - cipher suite */
const AES_128_CBC_SHA = from([0x00, 0x2f])
/** @constant {buffer} - signature algorithm */
const RSA_PKCS1_SHA256 = from([0x04, 0x01])
/** @constant {number} - for public key encryption padding */
const RSA_PKCS1_PADDING = crypto.constants.RSA_PKCS1_PADDING

/**
convert a uint8 number to a 1-byte buffer
@function
@param {number} i
@returns {buffer}
*/
const UInt8 = i => from([i])

/**
convert a uint16 number to a 2-byte buffer
@function
@param {number} i
@returns {buffer}
*/
const UInt16 = i => from([i >> 8, i])

/**
converts a uint24 number to a 3-byte buffer
@function
@param {number} i
@returns {buffer}
*/
const UInt24 = i => from([i >> 16, i >> 8, i])

/**
reads a uint24 number from the first 3-byte of a buffer
@function
@param {buffer} buf
@returns {number}
*/
const readUInt24 = buf => buf[0] * 65536 + buf[1] * 256 + buf[2]

/**
prepends 1-byte length to given buffer
@function
@param {buffer} b
@returns {buffer}
*/
const Prepend8 = b => concat([UInt8(b.length), b])

/**
prepends 2-byte length to given buffer
@function
@param {buffer} b
@returns {buffer}
*/
const Prepend16 = b => concat([UInt16(b.length), b])

/**
prepends 3-byte length to given buffer
@function
@param {buffer} b
@returns {buffer}
*/
const Prepend24 = b => concat([UInt24(b.length), b])

/**
generates a buffer with given size and filled with random bytes
@function
@param {number} size
@returns {buffer}
*/
const randomBuffer = size => randomFillSync(Buffer.alloc(size))

/**
calculates sha256 digest
@param {buffer} data
@returns {buffer}
*/
const SHA256 = data => createHash('sha256').update(data).digest()

/**
calculates sha1 hmac
@param {buffer} key - mac key
@param {buffer} data
@returns {buffer}
*/
const HMAC1 = (key, data) => createHmac('sha1', key).update(data).digest()

/**
calculates sha256 hmac
@param {buffer} key - mac key
@param {buffer} data
@returns {buffer}
*/
const HMAC256 = (key, data) => createHmac('sha256', key).update(data).digest()

/**
pseudo random function for key generation and expansion
@function
@param {buffer} secret
@param {string} label text
@param {buffer} seed
@param {number} length
@returns {buffer} buffer of given length
*/
const PRF256 = (secret, label, seed, length) => {
  seed = concat([from(label, 'binary'), seed])
  let P_HASH = Buffer.alloc(0)
  for (let A = from(seed); P_HASH.length < length;
    A = HMAC256(secret, A),
    P_HASH = concat([P_HASH, HMAC256(secret, concat([A, seed]))]));
  return P_HASH.slice(0, length)
}

/**
A sequence number function returns sequence number starting from 0
@typedef SequenceNumberFunction
@type {function}
@return {buffer}
*/

/**
create a sequence number function
@returns {SequenceNumberFunction}
*/
const createSequenceNumber = () => {
  const buf = Buffer.alloc(8)
  return () => {
    const r = from(buf)
    buf.writeUInt32BE(buf.readUInt32BE(4) + 1, 4)
    if (buf.readUInt32BE(4) === 0) {
      buf.writeUInt32BE(buf.readUInt32BE(0) + 1, 0)
      if (buf.readUInt32BE(0) === 0) throw new Error('sequence number overflow')
    }
    return r
  }
}

/**
A cipher function encrypts a tls record.
@typedef CipherFunction
@type {function}
@param {ContentType} type - tls record type
@param {buffer} data - tls record data (payload)
@returns {buffer} encrypted tls record
*/

/**
This is a (higher-order) factory function to generate a cipher function,
which maintains sequence number internally.
@function createCipher
@param {buffer} key - encryption key
@param {buffer} macKey - hmac key
@param {bigint} _iv - initial iv
@returns {CipherFunction}
*/
const createCipher = (key, macKey, _iv) => {
  const SN = createSequenceNumber()
  return (type, data) => {
    const iv = SHA256((++_iv).toString()).slice(0, 16)
    const tbs = concat([SN(), UInt8(type), VER12, Prepend16(data)])
    const mac = HMAC1(macKey, tbs)
    const len = 16 - (data.length + mac.length) % 16
    const pad = Buffer.alloc(len, len - 1)
    const c = createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
    return concat([iv, c.update(concat([data, mac, pad])), c.final()])
  }
}

/**
A decipher function decrypts a tls record.
@typedef DecipherFunction
@type {function}
@param {ContentType} type - tls record type
@param {buffer} data - encrypted tls record data
@returns {buffer} decrypted data (payload), mac verified and stripped
*/

/**
 * This is a higher order factory funtion to generate a decipher function,
 * which maintains sequence number internally.
 * @function createDecipher
 * @param {buffer} key - decryption key
 * @param {buffer} macKey - hmac key
 * @returns {DecipherFunction}
 */
const createDecipher = (key, macKey) => {
  const SN = createSequenceNumber()
  return (type, data) => {
    const iv = data.slice(0, 16)
    const d = createDecipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
    const dec = concat([d.update(data.slice(16)), d.final()])
    const len = dec[dec.length - 1] + 1
    if (dec.length < len) throw new Error('bad padding')
    const pad = dec.slice(dec.length - len)
    if (!pad.equals(Buffer.alloc(len, len - 1))) throw new Error('bad padding')
    data = dec.slice(0, dec.length - len - 20)
    const smac = dec.slice(dec.length - len - 20, dec.length - len)
    const tbs = concat([SN(), UInt8(type), VER12, Prepend16(data)])
    const cmac = HMAC1(macKey, tbs)
    if (!smac.equals(cmac)) throw new Error('mac mismatch')
    return data
  }
}

/**
 * convert a der certificate to pem format
 * @param {Buffer} der - certificate in DER format
 * @returns {string} certificate in PEM format
 */
const derToPem = der =>
`-----BEGIN CERTIFICATE-----
${der.toString('base64')}
-----END CERTIFICATE-----`

/**
 * execute a command using bash shell with given input
 * @param {string} cmd - command line
 * @param {string} input - data written to stdin
 * @param {function} callback - `(err, stdout, stderr) => {}`
 */
const bash = (cmd, input, callback) => {
  const c = child.exec(cmd, { shell: '/bin/bash' }, callback)
  c.stdin.write(input)
  c.stdin.end()
}

/**
 * verifies certificate chain using openssl
 * @param {string} cert - certificate to be verified
 * @param {string[]} intermediates - intermediate certificates
 * @param {string} ca - root ca certificates
 * @param {function} callback - `err => {}`
 */
const verifyCertificateChain = (cert, intermediates, ca, callback) => {
  const cmd = [
    `openssl verify -CAfile <(echo -e "${ca}")`,
    ...intermediates.map(i => `-untrusted <(echo -e "${i}")`)
  ].join(' ')

  bash(cmd, cert, (err, stdout, stderr) => {
    if (err) {
      callback(err)
    } else {
      if (stdout.toString().trim() === 'stdin: OK') {
        callback(null)
      } else {
        callback(new Error('verification failed'))
      }
    }
  })
}

/**
 * extracts public key from the certificate
 * @param {string} cert - certificate in PEM format
 * @param {function} callback - `(err, key) => {}`, key is a string.
 */
const extractPublicKey = (cert, callback) =>
  bash('openssl x509 -noout -pubkey', cert, callback)

/**
 * @typedef {Object} Fragment
 * @property {Number} type - content type
 * @property {Buffer} data - fragment data
 */

/**
 * @typedef {object} Message
 * @property {number} type - content type
 * @property {Buffer} data - message data (no fragment)
 */

/** handshake state context **/
class HandshakeContext {
  constructor () {
    /** cache all handshake messages except HELLO_REQUEST */
    this.buffer = []
    this.sessionId = 0
    this.clientRandom = randomBuffer(32)
    this.serverRandom = undefined
    this.preMasterSecret = concat([VER12, randomBuffer(46)])
    this.masterSecret = undefined
    this.clientWriteMacKey = undefined
    this.serverWriteMacKey = undefined
    this.clientWriteKey = undefined
    this.serverWriteKey = undefined
  }

  push (data) {
    this.buffer.push(data)
  }

  tbs () {
    return concat(this.buffer)
  }

  digest () {
    return SHA256(this.tbs())
  }

  lastType () {
    if (this.buffer.length) {
      return this.buffer[this.buffer.length - 1][0]
    } else {
      return 255
    }
  }

  deriveKeys () {
    this.masterSecret = PRF256(this.preMasterSecret, 'master secret',
      concat([this.clientRandom, this.serverRandom]), 48)

    const keys = PRF256(this.masterSecret, 'key expansion',
      concat([this.serverRandom, this.clientRandom]), 2 * (20 + 16) + 16)

    this.clientWriteMacKey = keys.slice(0, 20)
    this.serverWriteMacKey = keys.slice(20, 40)
    this.clientWriteKey = keys.slice(40, 56)
    this.serverWriteKey = keys.slice(56, 72)
    this.iv = Array.from(keys.slice(72))
      .reduce((sum, c, i) =>
        (sum + BigInt(c) << (BigInt(8) * BigInt(i))), BigInt(0))
  }

  clientVerifyData () {
    return PRF256(this.masterSecret, 'client finished', this.digest(), 12)
  }

  serverVerifyData () {
    return PRF256(this.masterSecret, 'server finished', this.digest(), 12)
  }
}

/**
Telsa is a TLS 1.2 client. Internally, there are four states:

#### `Connecting`

socket is connecting.

- `_write` is blocked.
- `_final` is allowed and triggers a transition to `Disconnected`.
- `_read` returns nothing.
- socket error triggers a transition to `Disconnected`; if there is `bufferredWrite`, error is passed via `callback`, otherwise, it is emitted.

#### `Handshaking`

- `_write` is blocked.
- `_final` triggers a transition to `Disconnected`. The callback is instantly invoked.
- socket error or message error triggers a transitoin to `Disconnected`.

#### `Established`
- `_write` is passed to socket connection. If blocking, the `callback` is blocked to next `Drain` event.
- `_final` triggers a transition to `Disconnected`; the callback is passed to underlying `socket.end()`.
- socket error or message error triggers a transitoin to `Disconnected`.

#### `Disconnected`
- `_write` returns error.
- `_final` succeeds anyway.
- `_read` returns nothing.
*/
class Telsa extends Duplex {
  /**
   * @param {object} opts
   */
  constructor (opts) {
    super(opts)

    /** options */
    this.opts = opts

    /**
     * blocked `_write` operation, also the write path state
     * - `null` if no blocked `_write`
     * - `{ chunk, encoding, callback }` if a `_write` is blocked
     * - `callback` if waiting for `drain` event
     * @type {object|function}
     */
    this.blocked = null

    /**
     * tcp connection
     * @type {net.Socket}
     */
    this.socket = net.createConnection(opts, () => {
      console.log('socket connected')

      this.state = 'Handshaking'

      /**
       * incomming data buffer, may contain fragmented records.
       * @type {Buffer}
       */
      this.incomming = Buffer.alloc(0)

      /**
       * current fragment, contains 0, 1 or more records of the same type.
       * @type {Fragment}
       */
      this.fragment = null

      /**
       * handshake context
       * @type {HandshakeContext}
       */
      this.hs = new HandshakeContext()

      /**
       * @type {CipherFunction}
       */
      this.cipher = null

      /**
       * @type {DecipherFunction}
       */
      this.decipher = null

      this.socket.on('data', data => this.handleSocketData(data))
      this.socket.on('error', err => this.handleSocketError(err))
      this.socket.on('close', () => this.handleSocketClose())

      // start handshaking
      this.sendClientHello()
    })

    this.socket.on('error', err => {
      console.log(err)
      this.state = 'Finished'
      this.socket = null
      this.emit('error', err)
    })

    this.state = 'Connecting'
  }

  /**
   * @return max fragment length
   */
  maxFragmentLength () {
    if (this.decipher) {
      return Math.pow(2, 14) + 2048
    } else {
      return Math.pow(2, 14)
    }
  }

  /**
   * read a record out of incomming data buffer
   * @returns {Fragment} the record type and payload
   */
  readFragment () {
    if (this.incomming.length < 1) return
    const type = this.incomming[0]
    if (type < 20 || type > 23) {
      throw new Error('bad content type')
    }

    if (this.incomming.length < 3) return
    const version = this.incomming.readUInt16BE(1)
    if (version !== 0x0303) {
      throw new Error('bad protocol version')
    }

    if (this.incomming.length < 5) return
    const length = this.incomming.readUInt16BE(3)

    if (length === 0 || length > this.maxFragmentLength) {
      throw new Error('bad fragment length')
    }

    if (this.incomming.length < 5 + length) return

    let data = this.incomming.slice(5, 5 + length)
    this.incomming = this.incomming.slice(5 + length)

    if (this.decipher) data = this.decipher(type, data)

    return { type, data }
  }

  /**
   * shift data chunk with given size from current fragment
   * @returns {Fragment}
   */
  shiftFragment (size) {
    if (!this.fragment || this.fragment.data.length < size) {
      throw new Error('inadequate size')
    }

    const type = this.fragment.type
    const data = this.fragment.data.slice(0, size)

    if (size === this.fragment.data.length) {
      this.fragment = null
    } else {
      this.fragment.data = this.fragment.data.slice(size)
    }

    return { type, data }
  }

  /**
   * read a message from current fragment
   * @returns {Message}
   */
  readMessageFromFragment () {
    if (!this.fragment) return
    switch (this.fragment.type) {
      case ContentType.ALERT:
        if (this.fragment.data.length < 2) return
        return this.shiftFragment(2)
      case ContentType.CHANGE_CIPHER_SPEC:
        return this.shiftFragment(1)
      case ContentType.HANDSHAKE: {
        if (this.fragment.data.length < 4) return
        const length = readUInt24(this.fragment.data.slice(1))
        if (this.fragment.data.length < 4 + length) return
        return this.shiftFragment(4 + length)
      }
      case ContentType.APPLICATION_DATA:
        return this.shiftFragment(this.fragment.data.length)
      default:
        throw new Error('invalid content type')
    }
  }

  /**
   * read a message
   * @returns {Message}
   */
  readMessage () {
    while (true) {
      const msg = this.readMessageFromFragment()
      if (msg) return msg
      const frag = this.readFragment()
      if (!frag) return

      if (this.fragment) {
        if (frag.type !== this.fragment.type) {
          throw new Error('unexpected fragment type')
        }
        this.fragment.data = Buffer.concat([this.fragment.data, frag.data])
      } else {
        this.fragment = frag
      }
    }
  }

  // TODO inline
  changeCipherSpec (key, macKey, iv) {
    this.sendChangeCipherSpec()
    this.cipher = createCipher(key, macKey, iv)
  }

  // TODO inline
  serverChangeCipherSpec (key, macKey) {
    this.decipher = createDecipher(key, macKey)
  }

  /**
   * handle socket data
   * @param {Buffer} data - socket data
   */
  handleSocketData (data) {
    this.incomming = Buffer.concat([this.incomming, data])
    while (true) {
      const msg = this.readMessage()
      if (!msg) return
      const { type, data } = msg
      switch (type) {
        case ContentType.ALERT:
          this.handleAlert(data)
          break
        case ContentType.CHANGE_CIPHER_SPEC:
          this.handleChangeCipherSpec(data)
          break
        case ContentType.HANDSHAKE:
          this.handleHandshakeMessage(data)
          break
        case ContentType.APPLICATION_DATA:
          this.handleApplicationData(data)
          break
        default:
          throw new Error('invalid type')
      }
    }
  }

  /**
   * handle alert message, all warnings are bypassed except `close_notify`
   * @param {Buffer} data
   */
  handleAlert (data) {
    // TODO
    console.log('handle alert')
  }

  /**
   * handle handshake message
   * @param {Buffer} msg - full message data, including type, length, and body
   */
  handleHandshakeMessage (msg) {
    const type = msg[0]
    const data = msg.slice(4)

    // TODO may reply no_renegotiation
    if (type === HandshakeType.HELLO_REQUEST) return

    switch (type) {
      case HandshakeType.SERVER_HELLO:
        this.handleServerHello(data)
        break
      case HandshakeType.CERTIFICATE:
        this.handleCertificate(data)
        break
      case HandshakeType.CERTIFICATE_REQUEST:
        this.handleCertificateRequest(data)
        break
      case HandshakeType.SERVER_HELLO_DONE:
        this.handleServerHelloDone(data)
        break
      case HandshakeType.FINISHED:
        this.handleServerFinished(data)
        break
      default:
        throw new Error('bad handshake message type')
    }
    this.hs.push(msg)
  }

  /**
   * ```
   * struct {
   *   ProtocolVersion server_version;
   *   Random random;
   *   SessionID session_id;
   *   CipherSuite cipher_suite;
   *   CompressionMethod compression_method;
   *   select (extensions_present) {
   *     case false:
   *       struct {};
   *     case true:
   *       Extension extensions<0..2^16-1>;
   *   };
   * } ServerHello;
   * ```
   */
  handleServerHello (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))

    const ProtocolVersion = shift(2)
    if (!ProtocolVersion.equals(VER12)) {
      throw new Error('unsupported tls version')
    }

    const Random = shift(32)
    this.hs.serverRandom = Random

    const SessionId = shift(shift(1)[0])
    this.hs.sessionId = SessionId

    const CipherSuite = shift(2)
    if (!CipherSuite.equals(AES_128_CBC_SHA)) {
      throw new Error('unsupported cipher suite')
    }

    const CompressionMethod = shift(1)[0]
    if (CompressionMethod !== 0) throw new Error('compression not supported')

    console.log('ServerHello', {
      ProtocolVersion: ProtocolVersion.toString('hex'),
      Random,
      SessionId,
      CipherSuite: CipherSuite.toString('hex'),
      CompressionMethod,
      data
    })
  }

  /**
   * ```
   * struct {
   *   ASN.1Cert certificate_list<0..2^24-1>;
   * } Certificate;
   * ```
   */
  handleCertificate (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))

    if (data.length < 3 || readUInt24(shift(3)) !== data.length) {
      throw new Error('invalid message length')
    }

    // certificates are in DER format and reversed order
    const ders = []
    while (data.length) {
      if (data.length < 3 || readUInt24(data) + 3 > data.length) {
        throw new Error('invalid cert length')
      }
      ders.push(shift(readUInt24(shift(3))))
    }

    // change to PEM format and reverse order
    const pems = ders.map(der => derToPem(der)).reverse()
    const pem = pems.pop()

    let failed = false
    let key = ''
    let verified = false

    verifyCertificateChain(pem, pems, this.opts.ca, err => {
      if (failed) return
      if (err) {
        failed = true
        error('verify', err)
      } else {
        verified = true
        success()
      }
    })

    extractPublicKey(pem, (err, stdout) => {
      if (failed) return
      if (err) {
        failed = true
        error('key', err)
      } else {
        key = stdout.toString()
        success()
      }
    })

    const error = (who, err) => {
      // TODO
    }

    const success = () => {
      if (key && verified) {
        this.hs.serverPublicKey = key
        this.sendClientCertificate()
      }
    }
  }

  /**
   * ```
   * struct {
   *   ClientCertificateType certificate_types<1..2^8-1>;
   *   SignatureAndHashAlgorithm
   *     supported_signature_algorithms<2^16-1>;
   *   DistinguishedName certificate_authorities<0..2^16-1>;
   * } CertificateRequest;
   * ```
   */
  handleCertificateRequest (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))
    if (data.length < 1 || data[0] + 1 > data.length) {
      throw new Error('invalid length')
    }

    this.hs.certificateTypes = Array.from(shift(shift(1)[0]))

    if (data.length < 2 || data.readUInt16BE() % 2 ||
      data.readUInt16BE() + 2 > data.length) {
      throw new Error('invalid length')
    }

    this.hs.signatureAlgorithms = Array
      .from(shift(shift(2).readUInt16BE()))
      .reduce((acc, c, i, arr) =>
        (i % 2) ? [...acc, arr[i - 1] * 256 + c] : acc, [])

    // ignore distinguished names (DER), observed 00 00

    console.log('CertificateRequest', {
      ClientCertificateType: this.hs.certificateTypes,
      SignatureAndHashAlgorithm: this.hs.signatureAlgorithms,
      data
    })
  }

  /**
   * struct { } ServerHelloDone;
   */
  handleServerHelloDone (data) {
    if (data.length) throw new Error('invalid server hello done')
    process.nextTick(() => this.sendClientCertificate())
  }

  handleServerFinished (data) {
    const verifyData = this.hs.serverVerifyData()
    if (!data.equals(verifyData)) throw new Error('verified failed')

    console.log('server finished')

    this.state = 'Established'
  }

  /**
   * handle change cipher spec
   */
  handleChangeCipherSpec (data) {
    // TODO expect
    console.log('handle change cipher spec', data)
    this.serverChangeCipherSpec(this.hs.serverWriteKey,
      this.hs.serverWriteMacKey)
  }

  /**
   * handle application data
   */
  handleApplicationData (data) {
    console.log('handle application data')
    if (this.state === 'Established') {
    } else {
      throw new Error('bad data')
    }
  }

  /**
   * record layer send data
   * @param {number} type - content type
   * @param {Buffer} data - content
   */
  send (type, data, callback) {
    if (this.cipher) data = this.cipher(type, data)
    const record = concat([UInt8(type), VER12, Prepend16(data)])
    return this.socket.write(record, callback)
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendAlert (level, description) {
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendChangeCipherSpec () {
    return this.send(ContentType.CHANGE_CIPHER_SPEC, from([1]))
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendHandshakeMessage (type, data) {
    console.log('sending: ' + handshakeTypeName(type))
    data = concat([UInt8(type), Prepend24(data)])
    this.hs.push(data)
    return this.send(ContentType.HANDSHAKE, data)
  }

  /**
   * send ClientHello
   */
  sendClientHello () {
    this.sendHandshakeMessage(HandshakeType.CLIENT_HELLO, concat([
      VER12,
      this.hs.clientRandom,
      from([0]), // session_id
      from([0x00, 0x02, 0x00, 0x2f]), // cipher_suites
      from([0x01, 0x00]) // compression_methods
    ]))
  }

  /**
   * send client certificate if ServerHelloDone and
   * server public key available (which also means server certificates
   * verified)
   */
  sendClientCertificate () {
    if (this.hs.serverPublicKey &&
      this.hs.lastType() === HandshakeType.SERVER_HELLO_DONE) {
      this.sendHandshakeMessage(HandshakeType.CERTIFICATE,
        Prepend24(concat([
          ...this.opts.clientCertificates.map(c => Prepend24(c))])))

      this.sendClientKeyExchange()
    }
  }

  /**
   * send ClientKeyExchange message, preMasterSecret is encrypted
   * using server's public key
   */
  sendClientKeyExchange () {
    this.sendHandshakeMessage(HandshakeType.CLIENT_KEY_EXCHANGE,
      Prepend16(publicEncrypt({
        key: this.hs.serverPublicKey,
        padding: RSA_PKCS1_PADDING
      }, this.hs.preMasterSecret)))

    this.sendCertificateVerify()
  }

  /**
   * send CertificateVerify, ChangeCipherSpec, and client Finished
   */
  sendCertificateVerify () {
    const key = this.opts.clientPrivateKey
    if (typeof key === 'function') {
    } else {
      const sig = createSign('sha256').update(this.hs.tbs()).sign(key)
      this.sendHandshakeMessage(HandshakeType.CERTIFICATE_VERIFY,
        concat([RSA_PKCS1_SHA256, Prepend16(sig)]))

      // change cipher spec
      this.hs.deriveKeys()
      const { clientWriteKey, clientWriteMacKey, iv } = this.hs
      this.changeCipherSpec(clientWriteKey, clientWriteMacKey, iv)

      // send finished
      this.sendHandshakeMessage(HandshakeType.FINISHED,
        this.hs.clientVerifyData())
    }
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendApplicationData (data) {
    console.log('sending: application data')
  }

  /**
   * implements `Duplex` `_write`
   */
  _write (chunk, encoding, callback) {
    if (this.state === 'Connecting' || this.state === 'Handshaking') {
      this.pendingWrite = { chunk, encoding, callback }
    } else if (this.state === 'Established') {
      if (this.sendApplication(chunk)) return callback()
      this.pendingWrite = { callback }
      this.socket.once('drain', () => {
        this.pendingWrite = null
        callback()
      })
    } else {
      const err = new Error('connection is ended')
      callback(err)
    }
  }

  /** implement Duplex _final */
  _final (callback) {
    if (this.state === 'Connecting') {
    } if (this.state === 'Handshaking') {
    } else if (this.state === 'Established') {
    } else {
      callback()
    }
  }

  /** implement Duplex _read */
  _read (size) {
    if (this.state === 'Established') this.socket.resume()
  }
}

module.exports = Telsa
