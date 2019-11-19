const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')
const {
  createHash, createHmac, createSign, createCipheriv,
  createDecipheriv, publicEncrypt, randomFillSync, constants
} = crypto

const { alloc, concat, from } = Buffer

const { asn1, pki } = require('node-forge')
const Debug = require('debug')

const logM = Debug('telsa:message')

/**
 * K combinator is a higher-order function which accepts two
 * expressions `x` and `y`. It evalutes `x` then `y` and
 * returns `x` finally. It is helpful for compact code.
 * @function
 */
const K = x => y => x

/** @constant {buffer} - TLS version 1.2 */
const VER12 = from([0x03, 0x03])
/** @constant {buffer} - cipher suite */
const AES_128_CBC_SHA = from([0x00, 0x2f])
/** @constant {buffer} - signature algorithm */
const RSA_PKCS1_SHA256 = from([0x04, 0x01])
/** @constant {number} - for public key encryption padding */
const RSA_PKCS1_PADDING = constants.RSA_PKCS1_PADDING

/**
 * reads a 24bit unsigned integer from the first 3-byte of a buffer
 * @param {buffer} buf
 * @returns {number}
 */
const readUInt24 = buf => buf[0] * 65536 + buf[1] * 256 + buf[2]

/**
 * prepends 2-byte length to given buffer
 * @param {buffer} b
 * @returns {buffer}
 */
const prepend16 = b => concat([from([b.length >> 8, b.length]), b])

/**
 * prepends 3-byte length to given buffer
 * @param {buffer} b
 * @returns {buffer}
 */
const prepend24 = b =>
  concat([from([b.length >> 16, b.length >> 8, b.length]), b])

/**
 * calculates sha256 digest
 * @param {buffer} data
 * @returns {buffer}
 */
const SHA256 = data => createHash('sha256').update(data).digest()

/**
 * calculates sha1 hmac
 * @param {buffer} key - mac key
 * @param {buffer} data
 * @returns {buffer}
 */
const HMAC1 = (key, data) => createHmac('sha1', key).update(data).digest()

/**
 * calculates sha256 hmac
 * @param {buffer} key - mac key
 * @param {buffer} data
 * @returns {buffer}
 */
const HMAC256 = (key, data) => createHmac('sha256', key).update(data).digest()

/**
 * pseudo random function for key generation and expansion, see rfc5246.
 *
 * @function
 * @param {buffer} secret
 * @param {string} label
 * @param {buffer} seed
 * @param {number} length
 * @returns {buffer} buffer of given length
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
 * A sequence number function returns sequence number starting from 0
 * @typedef SequenceNumberFunction
 * @type {function}
 * @return {buffer}
 */

/**
 * create a sequence number function
 * @returns {SequenceNumberFunction}
 */
const createSequenceNumber = () => {
  const buf = Buffer.alloc(8)
  return () => {
    const r = from(buf)
    buf.writeUInt32BE(buf.readUInt32BE(4) + 1, 4)
    if (buf.readUInt32BE(4) === 0) {
      buf.writeUInt32BE(buf.readUInt32BE(0) + 1, 0)

      // rfc5246, seq num should never overflow since it is a 64bit number
      // so this error is considered to be an internal error
      if (buf.readUInt32BE(0) === 0) {
        throw new Error('sequence number overflow')
      }
    }
    return r
  }
}

/**
 * A cipher function encrypts a tls record content.
 * @typedef CipherFunction
 * @type {function}
 * @param { type - tls record type
 * @param {buffer} data - tls record data (payload)
 * @returns {buffer} encrypted tls record
 */

/**
 * This is a (higher-order) factory function to generate a cipher function,
 * which maintains sequence number internally.
 * @function createCipher
 * @param {buffer} key - encryption key
 * @param {buffer} macKey - hmac key
 * @param {bigint} _iv - initial iv
 * @returns {CipherFunction}
 */
const createCipher = (key, macKey, _iv) => {
  const SN = createSequenceNumber()
  return (type, data) => {
    const iv = SHA256((++_iv).toString()).slice(0, 16)
    const tbs = concat([SN(), from([type]), VER12, prepend16(data)])
    const mac = HMAC1(macKey, tbs)
    const len = 16 - (data.length + mac.length) % 16
    const pad = Buffer.alloc(len, len - 1)
    const c = createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
    return concat([iv, c.update(concat([data, mac, pad])), c.final()])
  }
}

/**
 * A decipher function decrypts a tls record.
 * This function does NOT throw TLSError. The caller is resposible
 * for translating the thrown error to TLSError.
 *
 * @typedef DecipherFunction
 * @type {function}
 * @param { type - tls record type
 * @param {buffer} data - encrypted tls record data
 * @returns {buffer} decrypted data (payload), mac verified and stripped
 */

/**
 * This is a higher order factory funtion to generate a decipher function,
 * which maintains sequence number internally.
 *
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
    if (dec.length < len) {
      throw new Error('bad padding')
    }
    const pad = dec.slice(dec.length - len)
    if (!pad.equals(Buffer.alloc(len, len - 1))) {
      throw new Error('bad padding')
    }
    data = dec.slice(0, dec.length - len - 20)
    const smac = dec.slice(dec.length - len - 20, dec.length - len)
    const tbs = concat([SN(), from([type]), VER12, prepend16(data)])
    const cmac = HMAC1(macKey, tbs)

    if (!smac.equals(cmac)) throw new Error('mac mismatch')
    return data
  }
}

/** @enum {number} tls record content type */
const ContentType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
}

/**
 * @param {number} content type
 * @returns {string} content type name
 */
const contentType = type => {
  const {
    CHANGE_CIPHER_SPEC,
    ALERT,
    HANDSHAKE,
    APPLICATION_DATA
  } = ContentType

  switch (type) {
    case CHANGE_CIPHER_SPEC:
      return 'change_cipher_spec'
    case ALERT:
      return 'alert'
    case HANDSHAKE:
      return 'handshake'
    case APPLICATION_DATA:
      return 'application_data'
    default:
      throw new Error('unknown content type')
  }
}

/** @enum {number} - handshake message type */
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
 * @returns {string} handshake message type name
 */
const handshakeType = type => {
  const {
    HELLO_REQUEST,
    CLIENT_HELLO,
    SERVER_HELLO,
    CERTIFICATE,
    SERVER_KEY_EXCHANGE,
    CERTIFICATE_REQUEST,
    SERVER_HELLO_DONE,
    CERTIFICATE_VERIFY,
    CLIENT_KEY_EXCHANGE,
    FINISHED
  } = HandshakeType

  switch (type) {
    case HELLO_REQUEST:
      return 'HelloRequest'
    case CLIENT_HELLO:
      return 'ClientHello'
    case SERVER_HELLO:
      return 'ServerHello'
    case CERTIFICATE:
      return 'Certificate'
    case SERVER_KEY_EXCHANGE:
      return 'ServerKeyExchange'
    case CERTIFICATE_REQUEST:
      return 'CertificateRequest'
    case SERVER_HELLO_DONE:
      return 'ServerHelloDone'
    case CERTIFICATE_VERIFY:
      return 'CertificateVerify'
    case CLIENT_KEY_EXCHANGE:
      return 'ClientKeyExchange'
    case FINISHED:
      return 'Finished'
    default:
      throw new Error(`unknown handshake type ${type}`)
  }
}

/** @enum {number} tls alert level */
const AlertLevel = {
  WARNING: 1,
  FATAL: 2
}

/**
 * @param {number} alert level
 * @returns {string} alert level name
 */
const alertLevel = level => {
  switch (level) {
    case AlertLevel.WARNING:
      return 'warning'
    case AlertLevel.FATAL:
      return 'fatal'
    default:
      throw new Error(`unknown alert level ${level}`)
  }
}

/** 
 * TODO describe usage
 * @enum {number} alert description 
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

/**
 * @param {number} alert description
 * @returns {string} alert description name
 */
const alertDescription = desc => {
  const {
    CLOSE_NOTIFY,
    UNEXPECTED_MESSAGE,
    BAD_RECORD_MAC,
    DECRYPTION_FAILED_RESERVED,
    RECORD_OVERFLOW,
    DECOMPRESSION_FAILURE,
    HANDSHAKE_FAILURE,
    NO_CERTIFICATE_RESERVED,
    BAD_CERTIFICATE,
    UNSUPPORTED_CERTIFICATE,
    CERTIFICATE_REVOKED,
    CERTIFICATE_EXPIRED,
    CERTIFICATE_UNKNOWN,
    ILLEGAL_PARAMETER,
    UNKNOWN_CA,
    ACCESS_DENIED,
    DECODE_ERROR,
    DECRYPT_ERROR,
    EXPORT_RESTRICTION_RESERVED,
    PROTOCOL_VERSION,
    INSUFFICIENT_SECURITY,
    INTERNAL_ERROR,
    USER_CANCELED,
    NO_RENEGOTIATION,
    UNSUPPORTED_EXTENSION
  } = AlertDescription

  switch (desc) {
    case CLOSE_NOTIFY:
      return 'close_notify'
    case UNEXPECTED_MESSAGE:
      return 'unexpected_message'
    case BAD_RECORD_MAC:
      return 'bad_record_mac'
    case DECRYPTION_FAILED_RESERVED:
      return 'decryption_failed_reserved'
    case RECORD_OVERFLOW:
      return 'record_overflow'
    case DECOMPRESSION_FAILURE:
      return 'decompression_failure'
    case HANDSHAKE_FAILURE:
      return 'handshake_failure'
    case NO_CERTIFICATE_RESERVED:
      return 'no_certificate_reserved'
    case BAD_CERTIFICATE:
      return 'bad_certificate'
    case UNSUPPORTED_CERTIFICATE:
      return 'unsupported_certificate'
    case CERTIFICATE_REVOKED:
      return 'certificate_revoked'
    case CERTIFICATE_EXPIRED:
      return 'certificate_expired'
    case CERTIFICATE_UNKNOWN:
      return 'certificate_unknown'
    case ILLEGAL_PARAMETER:
      return 'illegal_parameter'
    case UNKNOWN_CA:
      return 'unknown_ca'
    case ACCESS_DENIED:
      return 'access_denied'
    case DECODE_ERROR:
      return 'decode_error'
    case DECRYPT_ERROR:
      return 'decrypt_error'
    case EXPORT_RESTRICTION_RESERVED:
      return 'export_restriction_reserved'
    case PROTOCOL_VERSION:
      return 'protocol_version'
    case INSUFFICIENT_SECURITY:
      return 'insufficient_security'
    case INTERNAL_ERROR:
      return 'internal_error'
    case USER_CANCELED:
      return 'user_canceled'
    case NO_RENEGOTIATION:
      return 'no_renegotiation'
    case UNSUPPORTED_EXTENSION:
      return 'unsupported_extension'
    default: // description may be extended by other spec
      return 'unknown_alert_description'
  }
}

/**
 * TLSError represents an error in handling tls protocol,
 * such as decoding or decryption error, malformatted message
 * or illegal value. It is not used for error emitted from
 * dependent components, such as socket or file system api.
 *
 * TLSError has no error code defined.
 */
class TLSError extends Error {
  /**
   * constructs a TLSError.
   *
   * If `msg` is an Error, TLSError preserves its properties, including
   * message and stack. If `msg` is string, it is used as error message.
   * If `msg` is not provided, TLSError use the alert description name as
   * error message.
   *
   * @param {number} desc - alert description
   * @param {string|Error} [msg] - error or error message
   */
  constructor (desc, msg) {
    if (msg instanceof Error) {
      super(msg.message)
      Object.assign(this, msg)
      this.stack = msg.stack
    } else {
      super(msg || alertDescription(desc))
    }

    this.name = this.name || this.constructor.name

    /** alert level */
    this.level = AlertLevel.FATAL
    /** alert description */
    this.description = desc
  }
}

/**
 * TLSAlert represents a tls alert received from the other party.
 *
 * TLSAlert has no error code defined.
 */
class TLSAlert extends Error {
  /**
   * constructs a TLSAlert
   * @param {number} desc - alert description
   * @param {number} [level] - alter level, defauts to `FATAL`
   */
  constructor (desc, level = AlertLevel.FATAL) {
    super(alertDescription(desc))

    this.name = this.constructor.name

    /** alert level */
    this.level = level
    /** alert description */
    this.description = desc
  }
}

/**
 * @typedef {object} Fragment
 * @property {number} type - content type
 * @property {Buffer} data - fragment data
 */

/**
 * @typedef {object} Message
 * @property {number} type - content type
 * @property {Buffer} data - message data (no fragment)
 */

/**
 * TODO
 *
 * #### States
 *
 * Telsa has four internal states:
 *
 * - Connecting
 * - Handshaking
 * - Established
 * - Terminated
 *
 * The following operations or events are *external* events
 * in terms of a state machine.
 * - `_write`
 * - `_final`
 * - `_read`
 * - socket error
 * - read path error when processing socket data, including:
 *   + tls protocol error, defined as alert description
 *   + operation errors returned from asynchronous operation
 *     * some errors are protocol error, such as certificate not verified
 *     * others are operation errors, such as child process crashed.
 *   + other exceptions
 * - write path error when executing `_write` operation:
 *   + all errors are exceptions (which is internal error in alert description)
 * - server alert
 *   + fatal alert
 *   + close_notify
 *   + other warning alerts other than close_notify
 * - close `without a server alert`
 *
 * #### Stateful Resources
 * - write path
 *   + if a `_write` operation cannot be performed immediately, it is blocked.
 *   + if the underlying socket `write` returns `false` during a `_write` operation.
 * - read path
 *   + the underlying socket may be paused
 *
 * #### Finish write path
 * - the underlying socket could be finished by `end` method.
 *
 * #### Finish read path
 * - the read path could be finished by push a null. This is only necessary
 * after the tls is connected.
 *
 * #### Connecting State
 *
 * In connecting state, only the following
 */
class Telsa extends Duplex {
  /**
   * TODO
   * @param {object} opts
   * @param {number} opts.port - server port 
   * @param {string} opts.host - server domain name
   * @param {string} opts.ca - root CA certificate in PEM format
   * @param {string} opts.cert - client certificate
   */
  constructor (opts) {
    super(opts)

    /** options */
    this.opts = opts

    if (!this.opts.ca) {
      throw new Error('ca not provided')
    }

    /** root ca in forge format */
    this.ca = pki.certificateFromPem(this.opts.ca)

    /** forge ca store */
    this.caStore = pki.createCaStore([this.ca])

    if (!this.opts.cert) {
      throw new Error('client certificate not provided')
    }

    /** client cert in PEM format */
    this.certPem = this.opts.cert
    /** client cert in forge format */
    this.cert = pki.certificateFromPem(this.certPem)
    /** client cert in forge asn1 format */
    this.certAsn1 = pki.certificateToAsn1(this.cert)
    /** client cert in DER format (Buffer) */
    this.certDer = Buffer.from(asn1.toDer(this.certAsn1).data, 'binary')

    /**
     * pending or draining `_write` operation
     * - `null` if no pending or drain `_write`
     * - `{ chunk, encoding, callback }` if a `_write` is pending in
     * `CONNECTING` or `HANDSHAKING` state
     * - `{ callback }` if the operation is waiting for draining in
     * `ESTABLISHED` state
     */
    this.writing = null

    /**
     * incomming data buffer, may contain fragmented records.
     */
    this.incomming = Buffer.alloc(0)

    /**
     * current fragment, contains 0, 1 or more records of the same content type
     * @type {Fragment|null}
     */
    this.fragment = null

    /** client random */
    this.clientRandom = randomFillSync(alloc(32))

    /** session id, received in ServerHello */
    this.sessionId = 0

    /** server random, received in ServerHello */
    this.serverRandom = undefined

    /** 
     * server certificates received in server Certificate, stored 
     * in forge format and original reversed order, with highest
     * authorities at last.
     */
    this.serverCertificates = []

    /** server public key extracted from server certificate, in  */
    this.serverPublicKey = undefined

    /** pre-master secret */
    this.preMasterSecret = concat([VER12, randomFillSync(alloc(46))])

    /** master secret */
    this.masterSecret = undefined

    /** client write mac key */
    this.clientWriteMacKey = undefined

    /** server write mac key */
    this.serverWriteMacKey = undefined

    /** client key */
    this.clientWriteKey = undefined

    /** server key */
    this.serverWriteKey = undefined

    /** handshake messages */
    this.msgs = []

    /** @type {CipherFunction} */
    this.cipher = null

    /** @type {DecipherFunction} */
    this.decipher = null

    /**
     * tcp connection
     * @type {net.Socket}
     */
    this.socket = this.opts.socket || net.createConnection(opts)
    this.socket.on('connect', () => {
      this.state = 'HANDSHAKING'

      /**
       * handshake context
       * @type {HandshakeContext}
       */
      this.socket.on('close', () => this.terminate('socket'))
      this.socket.on('data', data => {
        try {
          this.handleSocketData(data)
        } catch (e) {
          this.handleError(e)
        }
      })

      // start handshaking
      this.sendClientHello()
    })

    this.socket.on('error', err => this.terminate('socket', err))
    this.state = 'CONNECTING'
  }

  /**
   * handle errors from data handler, asynchronous operations, but not
   * socket error
   */
  handleError (e) {
    if (e instanceof TLSAlert) {
      this.terminate('alert', e)
    } else {
      this.terminate('error', e)
    }
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
    const {
      DECODE_ERROR,
      RECORD_OVERFLOW,
      BAD_RECORD_MAC
    } = AlertDescription

    if (this.incomming.length < 1) return
    const type = this.incomming[0]
    if (type < 20 || type > 23) {
      throw new TLSError(DECODE_ERROR, 'bad content type')
    }

    if (this.incomming.length < 3) return
    const version = this.incomming.readUInt16BE(1)
    if (version !== 0x0303) {
      throw new TLSError(DECODE_ERROR, 'bad protocol version')
    }

    if (this.incomming.length < 5) return
    const length = this.incomming.readUInt16BE(3)

    if (length === 0) {
      throw new TLSError(DECODE_ERROR, 'zero record payload length')
    }

    if (length > this.maxFragmentLength()) {
      throw new TLSError(RECORD_OVERFLOW, 'record overflow')
    }

    if (this.incomming.length < 5 + length) return

    let data = this.incomming.slice(5, 5 + length)
    this.incomming = this.incomming.slice(5 + length)

    if (this.decipher) {
      try {
        data = this.decipher(type, data)
      } catch (e) {
        /**
         * ```
         * RFC 4346, TLS v1.1, page 28
         * Note: Differentiating between bad_record_mac and decryption_failed
         *       alerts may permit certain attacks against CBC mode as used in
         *       TLS [CBCATT].  It is preferable to uniformly use the
         *       bad_record_mac alert to hide the specific type of the error.
         * ```
         */
        throw new TLSError(BAD_RECORD_MAC, e)
      }
    }

    return { type, data }
  }

  /**
   * shift data chunk with given size from current fragment
   * @returns {Fragment}
   */
  shiftFragment (size) {
    const { DECODE_ERROR } = AlertDescription
    if (!this.fragment || this.fragment.data.length < size) {
      throw new TLSError(DECODE_ERROR, 'bad fragment size')
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
    const { DECODE_ERROR } = AlertDescription

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
        throw new TLSError(DECODE_ERROR, 'invalid content type')
    }
  }

  /**
   * read a message
   * @returns {Message}
   */
  readMessage () {
    const { DECODE_ERROR } = AlertDescription

    while (true) {
      const msg = this.readMessageFromFragment()
      if (msg) return msg
      const frag = this.readFragment()
      if (!frag) return

      if (this.fragment) {
        if (frag.type !== this.fragment.type) {
          throw new TLSError(DECODE_ERROR, 'incomplete fragment')
        }
        this.fragment.data = Buffer.concat([this.fragment.data, frag.data])
      } else {
        this.fragment = frag
      }
    }
  }

  /**
   * save handshake message
   */
  saveMessage (from, msg) {
    if (from !== 'server' && from !== 'client') {
      throw new Error('invalid parameter')
    }
    msg.from = from
    this.msgs.push(msg)
  }

  /**
   * assert last handshake message from and type
   */
  assertLast (from, type) {
    const { UNEXPECTED_MESSAGE } = AlertDescription

    if (from !== 'server' && from !== 'client') {
      throw new Error('invalid parameter')
    }

    if (!this.msgs.length) {
      const msg =
        `expected ${handshakeType(type)} from ${from}, ` +
        'actual none'
      throw new TLSError(UNEXPECTED_MESSAGE, msg)
    }

    const last = this.msgs[this.msgs.length - 1]
    if (last.from !== from || last[0] !== type) {
      const msg =
        `expected ${handshakeType(type)} from ${from}, ` +
        `actual ${handshakeType(last[0])} from ${last.from}`
      throw new TLSError(UNEXPECTED_MESSAGE, msg)
    }
  }

  /** derive keys from pre-master secret, client and server random */
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

  /**
   * set server random and derives keys
   * @param {buffer} random - server random
   */
  setServerRandom (random) {
    this.serverRandom = random
    this.deriveKeys()
  }

  /** generates client verify data in client Finished message */
  clientVerifyData () {
    return PRF256(this.masterSecret, 'client finished',
      SHA256(concat(this.msgs)), 12)
  }

  /** generates server verify data in server Finsihed message */
  serverVerifyData () {
    return PRF256(this.masterSecret, 'server finished',
      SHA256(concat(this.msgs)), 12)
  }

  /**
   * send change cipher spec message and set cipher
   */
  changeCipherSpec () {
    this.sendChangeCipherSpec()
    this.cipher = createCipher(this.clientWriteKey,
      this.clientWriteMacKey, this.iv)
  }

  /**
   * set decipher
   */
  //  serverChangeCipherSpec (key, macKey) {
  //    this.decipher = createDecipher(key, macKey)
  //  }

  /**
   * handle socket data
   * @param {Buffer} data - socket data
   */
  handleSocketData (data) {
    const { DECODE_ERROR } = AlertDescription

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
          throw new TLSError(DECODE_ERROR, 'invalid content type')
      }
    }
  }

  /**
   * handle alert message, all warnings are bypassed except `close_notify`
   * @param {Buffer} data
   */
  handleAlert (data) {
    const { DECODE_ERROR, CLOSE_NOTIFY } = AlertDescription

    const level = data[0]
    const desc = data[1]

    if (level !== AlertLevel.WARNING && level !== AlertLevel.FATAL) {
      throw new TLSError(DECODE_ERROR, 'bad alert level')
    }

    if (level === AlertLevel.FATAL || desc === CLOSE_NOTIFY) {
      throw new TLSAlert(desc, level)
    } else {
      // TODO console.log(`tls server alert: ${alertDescription(desc)}`)
    }
  }

  /**
   * handle handshake message
   * @param {Buffer} msg - full message data, including type, length, and body
   */
  handleHandshakeMessage (msg) {
    const {
      HELLO_REQUEST,
      CLIENT_HELLO,
      SERVER_HELLO,
      CERTIFICATE,
      SERVER_KEY_EXCHANGE,
      CERTIFICATE_REQUEST,
      SERVER_HELLO_DONE,
      CERTIFICATE_VERIFY,
      CLIENT_KEY_EXCHANGE,
      FINISHED
    } = HandshakeType

    const { UNEXPECTED_MESSAGE, DECODE_ERROR } = AlertDescription

    const type = msg[0]
    const data = msg.slice(4)

    console.log('  -> ' + handshakeType(type))

    switch (type) {
      case HELLO_REQUEST: // TODO may reply no_renegotiation
        return
      case CLIENT_HELLO:
        throw new TLSError(UNEXPECTED_MESSAGE, 'unexpected client hello')
      case SERVER_HELLO:
        this.assertLast('client', CLIENT_HELLO)
        this.handleServerHello(data)
        this.saveMessage('server', msg)
        break
      case CERTIFICATE:
        this.assertLast('server', SERVER_HELLO)
        this.handleCertificate(data)
        this.saveMessage('server', msg)
        break
      case SERVER_KEY_EXCHANGE:
        throw new TLSError(UNEXPECTED_MESSAGE, 'unexpected server key exchange')
      case CERTIFICATE_REQUEST:
        this.assertLast('server', CERTIFICATE)
        this.handleCertificateRequest(data)
        this.saveMessage('server', msg)
        break
      case SERVER_HELLO_DONE:
        this.assertLast('server', CERTIFICATE_REQUEST)
        this.handleServerHelloDone(data)
        this.saveMessage('server', msg)
        this.sendCertificate()
        this.sendClientKeyExchange()
        this.sign((err, sig) => {
          try {
            if (this.state === 'TERMINATED') return
            if (err) throw err
            this.assertLast('client', CLIENT_KEY_EXCHANGE)
            this.sendCertificateVerify(sig)
            this.changeCipherSpec()
            this.sendFinished()
          } catch (e) {
            this.handleError(e)
          }
        })
        break
      case CERTIFICATE_VERIFY:
        throw new TLSError(UNEXPECTED_MESSAGE, 'unexpected certificate verify')
      case CLIENT_KEY_EXCHANGE:
        throw new TLSError(UNEXPECTED_MESSAGE, 'unexpected client key exchange')
      case FINISHED:
        this.assertLast('client', FINISHED)
        this.handleServerFinished(data)
        this.saveMessage('server', msg)
        break
      default:
        throw new TLSError(DECODE_ERROR, 'bad handshake message type')
    }
  }

  /**
   * ```
   * enum {
   *   signature_algorithms(13), (65535)
   * } ExtensionType;
   *
   * struct {
   *   ExtensionType extension_type;
   *   opaque extension_data<0..2^16-1>;
   * } Extension;
   *
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
    const { ILLEGAL_PARAMETER } = AlertDescription

    const serverVersion = shift(2)
    if (!serverVersion.equals(VER12)) {
      throw new TLSError(ILLEGAL_PARAMETER, 'unsupported tls version')
    }

    const random = shift(32)
    this.setServerRandom(random)

    const sessionId = shift(shift(1)[0])
    this.sessionId = sessionId

    const cipherSuite = shift(2)
    if (!cipherSuite.equals(AES_128_CBC_SHA)) {
      throw new TLSError(ILLEGAL_PARAMETER, 'unsupported cipher suite')
    }

    const compressionMethod = shift(1)[0]
    if (compressionMethod !== 0) {
      throw new TLSError(ILLEGAL_PARAMETER, 'compression not supported')
    }

    if (data.length) {
      /** 
       * rfc 5246
       * An extension type MUST NOT appear in the ServerHello unless the same
       * extension type appeared in the corresponding ClientHello.
       */
      throw new TLSError(ILLEGAL_PARAMETER, 'server hello has extensions')
    }

    logM('ServerHello', {
      serverVersion: serverVersion.toString('hex'),
      random: random.toString('hex'),
      sessionId: sessionId.toString('hex'),
      cipherSuite: cipherSuite.toString('hex'),
      compressionMethod,
      extension: null
    })
  }

  /**
   * extracts and verifies server certificates. If succeeded,
   * extracts server public key for futher usage.
   *
   * ```
   * struct {
   *   ASN.1Cert certificate_list<0..2^24-1>;
   * } Certificate;
   * ```
   */
  handleCertificate (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))
    const {
      DECODE_ERROR, BAD_CERTIFICATE, UNSUPPORTED_CERTIFICATE, 
      ILLEGAL_PARAMETER, CERTIFICATE_UNKNOWN, UNKNOWN_CA
    } = AlertDescription

    if (data.length < 3 || readUInt24(shift(3)) !== data.length) {
      throw new TLSError(DECODE_ERROR, 'invalid message length')
    }

    // certificates are in DER format and reversed order.
    // forge.pki use this order.
    // parse data to be an array of forge cert objects
    const certs = []
    while (data.length) {
      if (data.length < 3 || readUInt24(data) + 3 > data.length) {
        throw new TLSError(DECODE_ERROR, 'invalid cert length')
      }

      const der = shift(readUInt24(shift(3)))

      let certAsn1, cert
      try {
        certAsn1 = asn1.fromDer(der.toString('binary'))
      } catch (e) {
        console.log('asn1.fromDer failed()', e)
        throw new TLSError(BAD_CERTIFICATE,
          'failed to parse certificate')
      }

      try {
        cert = pki.certificateFromAsn1(certAsn1)
      } catch (e) {
        console.log('pki.certificateFromAsn1() failed', e)
        throw new TLSError(UNSUPPORTED_CERTIFICATE,
          'failed to construct forge certificate from given asn1 data')
      }

      certs.push(cert)
    }

    // server no cert
    if (!certs.length) {
      throw new TLSError(ILLEGAL_PARAMETER, 'no certificate')
    }

    this.serverCertificates = certs

    logM('Server Certificate', this.serverCertificates.map(cert => {
      const subject = [...cert.subject.attributes]
        .sort((a, b) => a.shortName > b.shortName)
        .reduce((o, a) => Object.assign(o, { [a.shortName]: a.value }), {})
      const issuer = [...cert.issuer.attributes]
        .sort((a, b) => a.shortName > b.shortName)
        .reduce((o, a) => Object.assign(o, { [a.shortName]: a.value }), {})
      const validity = cert.validity
      return { subject, issuer, validity }
    }))

    // verify domain name (CN)
    const attr = certs[0].subject.getField('CN')
    if (!attr || typeof attr.value !== 'string' || !attr.value.length) {
      throw new TLSError(CERTIFICATE_UNKNOWN, 'bad subject common name')
    }

    const commonName = 
      attr.value.startsWith('*') ? attr.value.slice(1) : attr.value

    if (!this.opts.host.endsWith(commonName)) {
      throw new TLSError(CERTIFICATE_UNKNOWN, 
        'certificate subject common name does NOT match host domain name')
    }
      
    const highest = certs.findIndex(cert => cert.isIssuer(this.ca))
    if (highest !== -1) {
      const chain = certs.slice(0, highest + 1)

      // skip check date for client may have bad time
      const opts = { validityCheckDate: null }
      try {
        if (pki.verifyCertificateChain(this.caStore, chain, opts)) return
      } catch (e) {
        console.log('pki.verifyCertificateChain() failed', e)
        throw new TLSError(CERTIFICATE_UNKNOWN, 'failed to verify cert chain')
      }
    }

    throw new TLSError(UNKNOWN_CA, 'server certificates untrusted')
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
    const { DECODE_ERROR } = AlertDescription

    if (data.length < 1 || data[0] + 1 > data.length) {
      throw new TLSError(DECODE_ERROR, 'invalid length')
    }

    const certificateTypes = Array.from(shift(shift(1)[0]))

    if (data.length < 2 || data.readUInt16BE() % 2 ||
      data.readUInt16BE() + 2 > data.length) {
      throw new TLSError(DECODE_ERROR, 'invalid length')
    }

    const supportedSignatureAlgorithms = Array
      .from(shift(shift(2).readUInt16BE()))
      .reduce((acc, c, i, arr) =>
        (i % 2) ? [...acc, arr[i - 1] * 256 + c] : acc, [])

    // ignore distinguished names (DER), observed 00 00
    // no idea what it looks like if non-null
    let certificateAuthorities
    try {
      certificateAuthorities = asn1.fromDer(data.toString('binary'))
    } catch (e) {
      throw new TLSError(DECODE_ERROR, 'invalid certificate_authorities')
    }

    logM('CertificateRequest', {
      certificateTypes,
      supportedSignatureAlgorithms,
      certificateAuthorities
    })
  }

  /**
   * struct { } ServerHelloDone;
   */
  handleServerHelloDone (data) {
    const { DECODE_ERROR } = AlertDescription
    if (data.length) {
      throw new TLSError(DECODE_ERROR, 'invalid ServerHelloDone')
    }
  }

  /**
   * checks `verify_data` in server Finished message, transits to
   * Established state or throw error
   *
   * ```
   * struct {
   *   opaque verify_data[verify_data_length];
   * } Finished;
   * ```
   * @param {Buffer} data
   */
  handleServerFinished (data) {
    const verifyData = this.serverVerifyData()
    if (!data.equals(verifyData)) {
      throw new TLSError(AlertDescription.DECRYPT_ERROR,
        'failed to verify server Finished')
    }

    process.nextTick(() => {
      // set state
      this.state = 'ESTABLISHED'

      // TODO console.log('telsa entering Established state')

      // enter Established state
      this.socket.on('drain', () => {
        if (this.writing) {
          const callback = this.writing.callback
          this.writing = null
          callback()
        }
      })

      if (this.writing) {
        const { chunk, encoding, callback } = this.writing
        this.writing = null
        this._write(chunk, encoding, callback)
      }
    })
  }

  /**
   * handle change cipher spec
   */
  handleChangeCipherSpec (data) {
    // TODO expect
    // TODO validate
    console.log('  -> ChangeCipherSpec', data)
    this.decipher = createDecipher(this.serverWriteKey, this.serverWriteMacKey)
  }

  /**
   * handle application data
   */
  handleApplicationData (data) {
    // TODO
    this.push(data)
  }

  /**
   * constructs a record layer packet and send
   * @param {number} type - content type
   * @param {Buffer} data - content
   */
  send (type, data) {
    if (this.cipher) data = this.cipher(type, data)
    const record = concat([from([type]), VER12, prepend16(data)])
    return this.socket.write(record)
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendAlert (level, description) {
    return this.send(ContentType.ALERT, from([level, description]))
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendChangeCipherSpec () {
    console.log('<- Change Cipher Spec')
    return this.send(ContentType.CHANGE_CIPHER_SPEC, from([1]))
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendHandshakeMessage (type, data) {
    console.log('<- ' + handshakeType(type))
    data = concat([from([type]), prepend24(data)])
    this.saveMessage('client', data)
    return this.send(ContentType.HANDSHAKE, data)
  }

  /**
   * send ClientHello handshake message
   */
  sendClientHello () {
    this.sendHandshakeMessage(HandshakeType.CLIENT_HELLO, concat([
      VER12,
      this.clientRandom,
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
  sendCertificate () {
    this.sendHandshakeMessage(HandshakeType.CERTIFICATE,
      prepend24(concat([prepend24(this.certDer)])))
  }

  /**
   * send ClientKeyExchange message, preMasterSecret is encrypted
   * using server's public key
   */
  sendClientKeyExchange () {
    this.sendHandshakeMessage(HandshakeType.CLIENT_KEY_EXCHANGE,
      prepend16(publicEncrypt({
        key: pki.publicKeyToPem(this.serverCertificates[0].publicKey),
        padding: RSA_PKCS1_PADDING
      }, this.preMasterSecret)))
  }

  /**
   * sign all handshake messages sent and received so far
   */
  sign (callback) {
    const key = this.opts.key
    const tbs = concat(this.msgs)
    if (typeof key === 'function') {
      key(tbs, callback)
    } else {
      const sig = createSign('sha256').update(tbs).sign(key)
      process.nextTick(() => callback(null, sig))
    }
  }

  /**
   * send CertificateVerify
   */
  sendCertificateVerify (sig) {
    this.sendHandshakeMessage(HandshakeType.CERTIFICATE_VERIFY,
      concat([RSA_PKCS1_SHA256, prepend16(sig)]))
  }

  /**
   * send Finished handshake message
   */
  sendFinished () {
    this.sendHandshakeMessage(HandshakeType.FINISHED,
      this.clientVerifyData())
  }

  /**
   * @return {boolean} false if buffer full
   */
  sendApplicationData (data, callback) {
    return this.send(ContentType.APPLICATION_DATA, data)
  }

  /**
   * implements `Duplex` `_write`
   */
  _write (chunk, encoding, callback) {
    switch (this.state) {
      // fallthrough
      case 'CONNECTING':
      case 'HANDSHAKING':
        this.writing = { chunk, encoding, callback }
        break
      case 'ESTABLISHED':
        if (this.sendApplicationData(chunk)) {
          callback()
        } else {
          this.writing = { callback }
        }
        break
      case 'TERMINATED':
        callback(new Error('This socket has been terminated'))
        break
      default:
        break
    }
  }

  /** implement Duplex _final */
  _final (callback) {
    callback()
    this.terminate('final')
  }

  _destroy (err, callback) {
    callback(err)
    this.terminate('destroy')
  }

  /** implement Duplex _read */
  _read (size) {
    if (this.state === 'ESTABLISHED') this.socket.resume()
  }

  /**
   * terminate is the one-for-all method to end the telsa.
   * unlike node tls, telsa terminates synchronously, which means
   * that there is no closing state. This is allowed in TLS spec.
   *
   * - final
   * - destroy
   * - socket, [err]
   * - error, TLSError | Error
   * - alert, TLSAlert
   * - (close_notify) redefined from alert
   */
  terminate (reason, err) {
    console.log('  terminate', this.state, reason, err && err.message)

    const {
      CLOSE_NOTIFY, USER_CANCELED,
      INTERNAL_ERROR
    } = AlertDescription

    // redefine close_notify
    if (reason === 'alert' && err.description === CLOSE_NOTIFY) {
      reason = 'close_notify'
      err = null
    }

    // send alert if socket available
    try {
      if ((reason === 'final' || reason === 'destroy') &&
        this.state === 'HANDSHAKING') {
        this.sendAlert(AlertLevel.WARNING, USER_CANCELED)
      }

      if (reason === 'final' ||
        reason === 'destroy' ||
        reason === 'close_notify') {
        this.sendAlert(AlertLevel.WARNING, CLOSE_NOTIFY)
      }

      if (reason === 'error') {
        if (err instanceof TLSError) {
          this.sendAlert(AlertLevel.FATAL, err.description)
        } else {
          this.sendAlert(AlertLevel.FATAL, INTERNAL_ERROR)
        }
      }
    } catch (e) { }

    // clean socket
    this.socket.removeAllListeners()
    this.socket.on('error', () => {})
    if (reason === 'destroy') {
      this.socket.destroy()
    } else {
      this.socket.end()
    }

    // end
    if (reason !== 'destroy') this.push(null)

    let callback
    if (this.writing) {
      callback = this.writing.callback
      this.writing = null
    }

    // socket close always an error TODO
    if (reason === 'socket') err = err || new Error('premature close')

    // close_notify cause error if
    // 1. handshaking
    // 2. draining write
    if (reason === 'close_notify') {
      if (this.state === 'HANDSHAKING') {
        err = new Error('server close')
      } else if (this.state === 'ESTABLISHED' && callback) {
        err = new Error('socket has been ended by the other party')
        err.code = 'EPIPE'
      }
    }

    // over-simplified TODO
    if (err && !err.code) {
      if (this.state === 'HANDSHAKING') {
        err.code = 'ERR_TLS_HANDSHAKE_FAILED'
      } else if (this.state === 'ESTABLISHED') {
        err.code = 'ERR_TLS_CONNECTION_FAILED'
      }
    }

    if (err) {
      if (callback) {
        callback(err)
      } else {
        this.emit('error', err)
      }
    }

    // duplex will emit close on its own for destroy
    if (reason !== 'destroy') {
      // read path `end` is emitted in nextTick()
      // emitting `close` in nextTick guarantee it is after `end`
      process.nextTick(() => this.emit('close'))
    }
  }
}

module.exports = Telsa
