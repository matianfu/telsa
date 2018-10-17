const path = require('path')
const fs = require('fs')
const child = require('child_process')
const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')
const { createHash, createHmac, createSign, createCipheriv,
  createDecipheriv, publicEncrypt, randomFillSync } = crypto

const { concat, from } = Buffer

/**
content type for TLS record layer
@readonly
@enum {number}
*/
const ContentType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
}

/**
handshake record type
@readonly
@enum {number} - 1 byte
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
alert description (warning or error)
@readonly
@enum {number} - 1 byte
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
  let buf = Buffer.alloc(8)
  return () => {
    let r = from(buf)
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
    let iv = SHA256((++_iv).toString()).slice(0, 16)
    let tbs = concat([SN(), UInt8(type), VER12, Prepend16(data)])
    let mac = HMAC1(macKey, tbs)
    let len = 16 - (data.length + mac.length) % 16
    let pad = Buffer.alloc(len, len - 1)
    let c = createCipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
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
This is a higher order factory funtion to generate a decipher function,
which maintains sequence number internally.
@function createDecipher
@param {buffer} key - decryption key
@param {buffer} macKey - hmac key
@returns {DecipherFunction}
*/
const createDecipher = (key, macKey) => {
  const SN = createSequenceNumber()
  return (type, data) => {
    let iv = data.slice(0, 16)
    let d = createDecipheriv('aes-128-cbc', key, iv).setAutoPadding(false)
    let dec = concat([d.update(data.slice(16)), d.final()])
    let len = dec[dec.length - 1] + 1
    if (dec.length < len) throw new Error('bad padding')
    let pad = dec.slice(dec.length - len)
    if (!pad.equals(Buffer.alloc(len, len - 1))) throw new Error('bad padding')
    data = dec.slice(0, dec.length - len - 20)
    let smac = dec.slice(dec.length - len - 20, dec.length - len)
    let tbs = concat([SN(), UInt8(type), VER12, Prepend16(data)])
    let cmac = HMAC1(macKey, tbs)
    if (!smac.equals(cmac)) throw new Error('mac mismatch')
    return data
  }
}

/**
base state class
*/
class State {
  /**
  construct a new state from either previous state or the TLS context
  @param {State|Context} soc
  */
  constructor (soc) {
    if (soc instanceof State) {
      this.ctx = soc.ctx
      this.deferred = soc.deferred
    } else {
      this.ctx = soc
    }
  }

  /**
  go to next state
  @param {State} NextState - next state
  @param {...*} args - rest parameters
  */
  setState (NextState, ...args) {
    let p = State.prototype
    let qs = []

    if (this instanceof State) {
      console.log('- exiting ' + this.constructor.name)
      for (p = Object.getPrototypeOf(this);
        !(NextState.prototype instanceof p.constructor);
        p.hasOwnProperty('exit') && p.exit.apply(this),
        p = Object.getPrototypeOf(p));

      this.exited = true
    }

    if (NextState) {
      let ctx = this instanceof State ? this.ctx : this
      let nextState = new NextState(this, ...args)
      ctx.state = nextState
      for (let q = NextState.prototype; q !== p;
        q.hasOwnProperty('enter') && qs.unshift(q),
        q = Object.getPrototypeOf(q));

      qs.forEach(q => q.enter.apply(ctx.state))
    }
  }

  _write (chunk, encoding, callback) {
    this.deferred = { chunk, encoding, callback }  
  }

  _final (callback) {
    this.deferred = { callback }
  }

  // do nothing
  _read (size) {
  }
}

/** init state, top level state */
class InitState extends State {
  connect (port, host) {
    this.setState(Connecting, port, host)
  }
}

/** socket connecting */
class Connecting extends State {
  constructor (soc, port, host) {
    super(soc) 
    let socket = new net.Socket()
    socket.on('error', err => this.setState(FinalState, err))
    socket.connect(port, host, () => {
      socket.removeAllListeners('error') 
      delete this.socket
      this.setState(ServerHello, socket) 
    })
    this.socket = socket
  }

  exit () {
    if (this.socket) {
      this.socket.removeAllListeners('error')
      this.on('error', () => {})
      this.socket.end()
      delete this.socket
    }
  }
}

/** socket connected */
class Connected extends State {
  constructor (soc, socket) {
    super(soc)
    if (soc instanceof Connected) {
      this.rp = soc.rp
    } else {
      this.rp = new RecordProtocol(socket)
    }
    this.rp.state = this
  }

  // virtual
  onCloseNotify () {
  }

  onSocketError (err) {
    this.setState(FinalState, err)
  }

  // virtual
  onSocketReadable () {
  }

  onSocketEnd (err) {
    if (err) {
      this.setState(FinalState, err)
    } else {
      this.ctx.push(null)
    }
  }

  onSocketFinish () {
  }

  onSocketClose () {
    this.setState(FinalState)
    this.ctx.emit('close')
  }

  exit () {
    this.rp.exit()
  }
}

/** final state */
class FinalState extends State {
  constructor (soc, err) {
    super(soc)
    if (err) this.ctx.emit('error', err)
    this.err = err
    this.EFINAL = new Error('stream finalized')
  }

  _write (chunk, encoding, callback) {
    callback(this.EFINAL)
  } 

  _final (callback) {
    callback(this.EFINAL)
  }
}

/** tls record protocol */
class RecordProtocol {
  constructor (socket) {
    this.socket = socket
    this.data = Buffer.alloc(0)
    this.frag = Buffer.alloc(0)
    this.fragType = 255
    this.cipher = null
    this.decipher = null

    this.closeNotified = false

    // readable ended according to socket 
    this.readEnded = false
    // writable ended for end() is called 
    this.writeEnded = false
    // socket ever emitted error, not used
    this.errored = false
    // socket is fully closed, not used
    this.closed = false

    socket.on('end', () => {
      this.readEnded = true
      let err = null
      if (this.closeNotified === false) {
        err = new Error('server close without a close_notify')
      }

      this.state.onSocketEnd(err)
    })

    socket.on('finish', () => this.state.onSocketFinish())
    socket.on('close', () => this.state.onSocketClose())
    socket.on('error', err => this.state.onSocketError(err))
    // socket is in paused mode
    socket.on('readable', () => this.state.onSocketReadable())
  }

  exit () {
    this.socket.removeAllListeners()
    this.socket.on('error', () => {})
    this.end()
  }

  // record layer emit alert
  onAlert (data) {
    if (data.equals(CloseNotify)) {
      this.closeNotified = true
      this.end()
      this.state.onCloseNotify()
      return
    }

    let err = new Error('server alert') 
    err.code = 'EALERT'
    switch (data[0]) {
      case 1:
        err.level = 'WARNING'
        break
      case 2: 
        err.level = 'FATAL'
        break
      default:
        err.level = data[0]
        break
    } 

    // set alert description
    for (let prop in AlertDescription) {
      if (AlertDescription[prop] === data[1]) {
        err.description = prop
      }
    }

    throw err
  }

  /**
  handle fragment
  @param {ContentType} type
  @param {buffer} frag
  */
  onFragment (type, frag) {
    const shift = size => K(this.frag.slice(0, size))(this.frag = this.frag.slice(size))

    if (this.frag.length) {
      if (this.fragType !== type) throw new Error('fragment type mismatch')
      this.frag = concat([this.frag, frag])
    } else {
      this.frag = frag
      this.fragType = type
    }

    while (this.frag.length) {
      if (this.closeNotified) {
        throw new Error('data after close_notify')
      }
      
      switch (type) {
        case ContentType.CHANGE_CIPHER_SPEC:
          if (this.frag[0] !== 1) throw new Error('bad change ciper spec')
          this.state.onChangeCipherSpec(shift(1))
          break
        case ContentType.ALERT:
          if (this.frag.length < 2) return
          this.onAlert(shift(2))
          break
        case ContentType.HANDSHAKE:
          if (this.frag.length < 4) return
          let length = readUInt24(this.frag.slice(1))
          if (this.frag.length < 4 + length) return
          this.state.onHandshake(shift(4 + length))
          break
        case ContentType.APPLICATION_DATA:
          this.state.onApplicationData(shift(this.frag.length))
          break
        default: {
          throw new Error('exception')
        }
      }
    }
  }

  /**
  handle socket data
  @param {buffer} data
  */
  onData (data) {
    this.data = concat([this.data, data])
    while (this.data.length >= 5) {
      let type = this.data[0]
      if (type < 20 || type > 23) throw new Error('unknown content type')
      let version = this.data.readUInt16BE(1)
      if (version !== 0x0303) throw new Error('unsupported protocol version')
      let length = this.data.readUInt16BE(3)
      if (this.data.length < 5 + length) break
      let frag = this.data.slice(5, 5 + length)
      this.data = this.data.slice(5 + length)
      if (this.decipher) frag = this.decipher(type, frag)
      this.onFragment(type, frag)
    }
  }

  changeCipherSpec (key, macKey, iv) {
    this.write(ContentType.CHANGE_CIPHER_SPEC, from([1]))
    this.cipher = createCipher(key, macKey, iv)
  }

  /**
  
  */
  serverChangeCipherSpec (key, macKey) {
    this.decipher = createDecipher(key, macKey)
  }

  /**
  write data
  @param {ContentType} type
  @param {buffer} data
  @param {function} [callback]
  */
  write (type, data, callback) {
    if (this.writeEnded) {
      if (callback) callback(new Error('underlying socket ended'))
    } else {
      if (this.cipher) data = this.cipher(type, data)
      let record = concat([UInt8(type), VER12, Prepend16(data)])
      this.socket.write(record, callback)
    }
  }

  /**
  */
  end (callback) {
    if (this.writeEnded) {
      if (callback) callback()
    } else {
      this.write(ContentType.ALERT, CloseNotify)
      this.socket.end(callback) 
      this.writeEnded = true
    }
  }

  /**
  read data from underlying socket.
  */
  read () {
    if (this.readEnded) return
    if (this.socket.readableLength) {
      this.onData(this.socket.read())
    }
  }
}

/** handshake state context **/
class HandshakeContext {
  constructor () {
    this.buffer = []
    this.sessionId = 0
    this.clientRandom = randomBuffer(32)
    this.preMasterSecret = concat([VER12, randomBuffer(46)])
    this.masterSecret = undefined
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

  deriveKeys () {
    this.masterSecret = PRF256(this.preMasterSecret, 'master secret',
      concat([this.clientRandom, this.serverRandom]), 48)

    let keys = PRF256(this.masterSecret, 'key expansion',
      concat([this.serverRandom, this.clientRandom]), 2 * (20 + 16) + 16)

    this.clientWriteMacKey = keys.slice(0, 20)
    this.serverWriteMacKey = keys.slice(20, 40)
    this.clientWriteKey = keys.slice(40, 56)
    this.serverWriteKey = keys.slice(56, 72)
    this.iv = Array.from(keys.slice(72))
      .reduce((sum, c, i) => (sum + BigInt(c) << (BigInt(8) * BigInt(i))), BigInt(0))
  }

  clientVerifyData () {
    return PRF256(this.masterSecret, 'client finished', this.digest(), 12)
  }

  serverVerifyData () {
    return PRF256(this.masterSecret, 'server finished', this.digest(), 12)
  }
}

/**
A super-state for all handshake states
*/
class HandshakeState extends Connected {
  constructor (soc, ...args) {
    super(soc, ...args)
    this.hs = soc instanceof HandshakeState ? soc.hs : new HandshakeContext()
  }

  onSocketReadable () {
    try {
      this.rp.read()
    } catch (e) {
      this.setState(FinalState, e)
    }
  }

  onHandshake (data) {
    if (data[0] === HandshakeType.HELLO_REQUEST) return
    if (data[0] !== HandshakeType.FINISHED) this.hs.push(data)
    switch (data[0]) {
      case HandshakeType.SERVER_HELLO:
        this.onServerHello(data.slice(4))
        break
      case HandshakeType.CERTIFICATE:
        this.onCertificate(data.slice(4))
        break
      case HandshakeType.CERTIFICATE_REQUEST:
        this.onCertificateRequest(data.slice(4))
        break
      case HandshakeType.SERVER_HELLO_DONE:
        this.onServerHelloDone(data.slice(4))
        break
      case HandshakeType.FINISHED:
        this.onFinished(data.slice(4))
        break
      default:
        throw new Error('unsupported handshake message type')
    }
  }

  write (type, data) {
    data = concat([UInt8(type), Prepend24(data)])
    this.hs.push(data)
    this.rp.write(ContentType.HANDSHAKE, data)
  }
}

/** send client hello and expect server hello */
class ServerHello extends HandshakeState {
  enter () {
    this.write(HandshakeType.CLIENT_HELLO, concat([
      VER12,
      this.hs.clientRandom,
      from([0]), // session_id
      from([0x00, 0x02, 0x00, 0x2f]), // cipher_suites
      from([0x01, 0x00]) // compression_methods
    ]))
  }

  onServerHello (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))
    if (!shift(2).equals(VER12)) throw new Error('unsupported tls version')
    this.hs.serverRandom = shift(32)
    this.hs.sessionId = shift(shift(1)[0])
    if (!shift(2).equals(AES_128_CBC_SHA)) throw new Error('unsupported cipher suite')
    if (shift(1)[0] !== 0) throw new Error('unsupported compression')
    // ignore remaining bytes
    this.setState(ServerCertificate)
  }
}

/** expect server certificate message */
class ServerCertificate extends HandshakeState {
  onCertificate (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))
    if (data.length < 3 ||
      readUInt24(shift(3)) !== data.length) throw new Error('invalid message length')

    this.hs.serverCertificates = []
    while (data.length) {
      if (data.length < 3 ||
        readUInt24(data) + 3 > data.length) throw new Error('invalid cert length')
      this.hs.serverCertificates.push(shift(readUInt24(shift(3))))
    }

    // verify server certificates are deferred to
    let input = this.hs.serverCertificates[0]
    let cmd = 'openssl x509 -inform der -noout -pubkey'
    this.hs.serverPublicKey = child.execSync(cmd, { input })
    this.setState(CertificateRequest)
  }
}

/** expect certificate request */
class CertificateRequest extends HandshakeState {
  onCertificateRequest (data) {
    const shift = size => K(data.slice(0, size))(data = data.slice(size))

    if (data.length < 1 || data[0] + 1 > data.length) throw new Error('invalid length')
    this.hs.certificateTypes = Array.from(shift(shift(1)[0]))

    if (data.length < 2 || data.readUInt16BE() % 2 ||
      data.readUInt16BE() + 2 > data.length) throw new Error('invalid length')
    this.hs.signatureAlgorithms = Array
      .from(shift(shift(2).readUInt16BE()))
      .reduce((acc, c, i, arr) => (i % 2) ? [...acc, arr[i - 1] * 256 + c] : acc, [])
    // ignore distinguished names
    this.setState(ServerHelloDone)
  }
}

/** expect server hello done */
class ServerHelloDone extends HandshakeState {
  onServerHelloDone (data) {
    if (data.length) throw new Error('invalid server hello done')
    this.write(HandshakeType.CERTIFICATE, Prepend24(concat([
      ...this.ctx.opts.clientCertificates.map(c => Prepend24(c))])))
    this.write(HandshakeType.CLIENT_KEY_EXCHANGE, Prepend16(publicEncrypt({
      key: this.hs.serverPublicKey,
      padding: RSA_PKCS1_PADDING
    }, this.hs.preMasterSecret)))
    this.setState(VerifyServerCertificate)
  }
}

/** verify server certificate */
class VerifyServerCertificate extends HandshakeState {
  enter () {
    let ca = this.ctx.opts.ca
    // convert DER to PEM
    let pems = this.hs.serverCertificates
      .map(c => c.toString('base64'))
      .map(c => `-----BEGIN CERTIFICATE-----\n${c}\n-----END CERTIFICATE-----`)

    // create ca bundle
    let cert = pems.shift()
    pems.reverse()
    pems.unshift(ca)
    let bundle = pems.join('\n')

    let cmd = `openssl verify -CAfile <(echo -e "${bundle}")`
    this.openssl = child.exec(cmd, { shell: '/bin/bash' }, (err, stdout) => {
      if (this.exited) return
      let token = stdout.trim()
      if (err) {
        this.setState(FinalState, err)
      } else if (token === 'stdin: OK') {
        this.setState(CertificateVerify)
      } else {
        let err = new Error(`unexpect openssl output: ${token}`)
        this.setState(FinalState, err)
      }
    })
    this.openssl.stdin.write(cert)
    this.openssl.stdin.end()
  }
}

/** expect certificate verify */
class CertificateVerify extends HandshakeState {
  enter () {
    let key = this.ctx.opts.clientPrivateKey
    if (typeof key === 'function') {
    } else {
      let sig = createSign('sha256').update(this.hs.tbs()).sign(key)
      // send certificate verify
      this.write(HandshakeType.CERTIFICATE_VERIFY,
        concat([RSA_PKCS1_SHA256, Prepend16(sig)]))
      // change cipher spec
      this.hs.deriveKeys()
      let { clientWriteKey, clientWriteMacKey, iv } = this.hs
      this.rp.changeCipherSpec(clientWriteKey, clientWriteMacKey, iv)
      // send finished
      this.write(HandshakeType.FINISHED, this.hs.clientVerifyData())
      process.nextTick(() => this.setState(ChangeCipherSpec))
    }
  }
}

/** expect server change cipher spec */
class ChangeCipherSpec extends HandshakeState {
  onChangeCipherSpec () {
    this.rp.serverChangeCipherSpec(this.hs.serverWriteKey, this.hs.serverWriteMacKey)
    this.setState(ServerFinished)
  }
}

/** expect server finished **/
class ServerFinished extends HandshakeState {
  onFinished (data) {
    let verifyData = this.hs.serverVerifyData()
    if (!data.equals(verifyData)) throw new Error('verify data mismatch')
    this.setState(Established)
  }
}

/**
secure connection established
*/
class Established extends Connected {
  enter () {
    this.ctx.emit('connect')
    this.pushable = true

    if (this.deferred) {
      let { chunk, encoding, callback } = this.deferred
      this.deferred = null

      if (chunk) {
        this._write(chunk, encoding, callback)
      } else {
        this._final(callback)
      }
    }
  }

  onApplicationData (data) {
    if (data.length) this.pushable = this.ctx.push(data)
  }

  onSocketReadable () {
    if (this.pushable) {
      try {
        this.rp.read()
      } catch (e) {
        this.setState(FinalState, e)
      }
    }
  }

  onCloseNotify () {
    // TODO there may be pending write callback
    this.ctx.end()
  }

  // override
  _write (data, encoding, callback) {
    this.rp.write(ContentType.APPLICATION_DATA, data, callback)
  }

  // override
  _final (callback) {
    this.rp.end(callback)
  }

  // override
  _read (size) {
    try {
      this.rp.read()
    } catch (e) {
      this.setState(FinalState, e)
    }
  }
}

/**
context class of TLS state machine
*/
class Context extends Duplex {
  constructor (opts, socket) {
    super(opts)
    /**
    @member {Object}
    */
    this.opts = opts

    State.prototype.setState.apply(this, [InitState])
  }

  /**
  implement duplex _write
  */
  _write (chunk, encoding, callback) {
    this.state._write(chunk, encoding, callback)
  }

  /**
  implement duplex _final
  */
  _final (callback) {
    this.state._final(callback)
  }

  /**
  implement duplex _read
  */
  _read (size) {
    this.state._read(size)
  }

  /**
  connect is only availabe in Init state
  */
  connect (port, host, listener) {
    this.state.connect(port, host)
    if (listener) this.on('connect', () => listener())
  }
}

module.exports = Context
