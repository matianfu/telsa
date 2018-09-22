const path = require('path')
const fs = require('fs')
const child = require('child_process')
const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')

/**
enum {
    change_cipher_spec(20), alert(21), handshake(22),
    application_data(23), (255)
} ContentType;
*/
const CHANGE_CIPHER_SPEC = 20
const ALERT = 21
const HANDSHAKE = 22
const APPLICATION_DATA = 23

/**
enum {
    hello_request(0), client_hello(1), server_hello(2),
    certificate(11), server_key_exchange (12),
    certificate_request(13), server_hello_done(14),
    certificate_verify(15), client_key_exchange(16),
    finished(20), (255)
} HandshakeType;
*/
const HELLO_REQUEST = 0
const CLIENT_HELLO = 1
const SERVER_HELLO = 2
const CERTIFICATE = 11
const SERVER_KEY_EXCHANGE = 12
const CERTIFICATE_REQUEST = 13
const SERVER_HELLO_DONE = 14
const CERTIFICATE_VERIFY = 15
const CLIENT_KEY_EXCHANGE = 16
const FINISHED = 20

const TLSVersion = Buffer.from([0x03, 0x03])
const AES_128_CBC_SHA = Buffer.from([0x00, 0x2f])

const K = x => y => x

const UInt8 = i => Buffer.from([i])
const UInt16 = i => Buffer.from([i >> 8, i])
const UInt24 = i => Buffer.from([i >> 16, i >> 8, i])
const readUInt24 = buf => buf[0] * 65536 + buf[1] * 256 + buf[2]
const Prepend8 = b => Buffer.concat([UInt8(b.length), b])
const Prepend16 = b => Buffer.concat([UInt16(b.length), b])
const Prepend24 = b => Buffer.concat([UInt24(b.length), b])

const PRF = (secret, label, seed, length, hashType) => {
  seed = Buffer.concat([Buffer.from(label, 'binary'), seed])
  let A = Buffer.from(seed)
  let P_HASH = Buffer.alloc(0)
  for (let i = 0; i < Math.ceil(length / 32); ++i) {
    A = crypto.createHmac(hashType, secret).update(A).digest()
    let hmac = crypto.createHmac(hashType, secret)
      .update(Buffer.concat([A, seed])).digest()
    P_HASH = Buffer.concat([P_HASH, hmac])
  }
  return P_HASH.slice(0, length)
}

const createSequenceNumber = () => {
  let buf = Buffer.alloc(8)
  const read = () => {
    let r = buf.slice(0)
    buf.writeUInt32BE(buf.readUInt32BE(4) + 1, 4)
    if (buf.readUInt32BE(4) === 0) {
      buf.writeUInt32BE(buf.readUInt32BE(0) + 1, 0)
      if (buf.readUInt32BE(0) === 0) throw new Error('sequence number overflow')
    }
    return r
  }
  read.peek = () => buf // for debug
  return read
}

class State {
  constructor (ctx) {
    this.ctx = (ctx instanceof State) ? ctx.ctx : ctx
  }

  exit () { }

  setState (NextState, ...args) {
    for (let p = Object.getPrototypeOf(this);
      !(NextState.prototype instanceof p.constructor);
      p.hasOwnProperty('exit') && p.exit.apply(this),
      p = Object.getPrototypeOf(p));

    this.ctx.state = new NextState(this, ...args)
  }

  write (type, data) {
    this.ctx.write(type, data)
  }

  handleChangeCiperSpec (data) {
    throw new Error('unexpected change cipher spec')
  }

  handleAlert (data) {
    console.log('server alert', data)
  }

  handleHandshake (data) {
    throw new Error('unexpected handshake')
  }

  handleApplicationData (data) {
    throw new Error('unexpected application data')
  }
}

// this is a super state
class HandshakeState extends State {
  constructor (ctx) {
    super(ctx)
    if (ctx instanceof HandshakeState) {
      this.hs = ctx.hs
    } else {
      let clientRandom = crypto.randomFillSync(Buffer.alloc(32))
      let preMasterSecret = Buffer.concat([
        Buffer.from([0x03, 0x03]),
        crypto.randomFillSync(Buffer.alloc(46))
      ])

      this.hs = {
        buffer: [],
        sessionId: 0,
        clientRandom,
        preMasterSecret,
        tbs () {
          return Buffer.concat(this.buffer)
        },
        digest () {
          return crypto.createHash('sha256').update(this.tbs()).digest()
        },
        deriveKeys () {
          this.masterSecret = PRF(this.preMasterSecret, 'master secret',
            Buffer.concat([this.clientRandom, this.serverRandom]),
            48, 'sha256')

          let keys = PRF(this.preMasterSecret, 'key expansion',
            Buffer.concat([this.serverRandom, this.clientRandom]),
            2 * (20 + 16) + 16, 'sha256')

          this.clientWriteMacKey = keys.slice(0, 20)
          this.serverWriteMacKey = keys.slice(20, 40)
          this.clientWriteKey = keys.slice(40, 56)
          this.serverWriteKey = keys.slice(56, 72)

          // this is not the standard
          this.ivKey = Array.from(keys.slice(72))
            .reduce((sum, c, i) =>
              (sum + BigInt(c) << (BigInt(8) * BigInt(i))), BigInt(0))
        },
        clientVerifyData () {
          return PRF(this.masterSecret, 'client finished',
            this.digest(), 12, 'sha256')
        },
        serverVerifyData () {
          return PRF(this.hs.masterSecret, 'server finished',
            this.digest(), 12, 'sha256')
        }
      }
    }
  }

  // override
  write (type, data) {
    console.log('handshake write', type, data)
    data = Buffer.concat([UInt8(type), Prepend24(data)])
    this.hs.buffer.push(data)
    super.write(HANDSHAKE, data)
  }

  changeCipherSpec () {
    this.hs.deriveKeys()
    super.write(CHANGE_CIPHER_SPEC, Buffer.from([1]))
    this.ctx.createCipher(this.hs.clientWriteKey, this.hs.clientWriteMacKey, this.hs.iv)
  }

  serverChangeCipherSpec () {
    this.ctx.createDecipher(this.hs.serverWriteKey, this.hs.serverWriteMacKey)
  }

  handleHandshake (data) {
    if (data[0] === HELLO_REQUEST) return
    switch (data[0]) {
      case SERVER_HELLO:
        this.handleServerHello(data.slice(4))
        break
      case CERTIFICATE:
        this.handleCertificate(data.slice(4))
        break
      case CERTIFICATE_REQUEST:
        this.handleCertificateRequest(data.slice(4))
        break
      case SERVER_HELLO_DONE:
        this.handleServerHelloDone(data.slice(4))
        break
      case FINISHED:
        this.handleFinished(data.slice(4))
        break
      default:
        throw new Error('unsupported handshake message type')
    }
    this.hs.buffer.push(data) // ! after message handled
  }
}

class ServerHello extends HandshakeState {
  constructor (ctx) {
    super(ctx)
    this.write(CLIENT_HELLO, Buffer.concat([
      TLSVersion,
      this.hs.clientRandom,
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
  }

  handleServerHello (data) {
    const unshift = size => K(data.slice(0, size))(data = data.slice(size))
    if (!unshift(2).equals(TLSVersion)) throw new Error('unsupported tls version')
    this.hs.serverRandom = unshift(32)
    this.hs.sessionId = unshift(unshift(1)[0])
    if (!unshift(2).equals(AES_128_CBC_SHA)) throw new Error('unsupported cipher suite')
    if (unshift(1)[0] !== 0) throw new Error('unsupported compression')
    // ignore remaining bytes
    this.setState(ServerCertificate)
  }
}

class ServerCertificate extends HandshakeState {
  handleCertificate (data) {
    const unshift = size => K(data.slice(0, size))(data = data.slice(size))
    if (data.length < 3 || readUInt24(unshift(3)) !== data.length) {
      throw new Error('invalid message length')
    }

    this.hs.serverCertificates = []
    while (data.length) {
      if (data.length < 3 || readUInt24(data) + 3 > data.length) {
        throw new Error('invalid cert length')
      }
      this.hs.serverCertificates.push(unshift(readUInt24(unshift(3))))
    }

    // TODO verify certificate change

    let input = this.hs.serverCertificates[0]
    let cmd = 'openssl x509 -inform der -noout -pubkey'
    this.hs.serverPublicKey = child.execSync(cmd, { input })
    this.setState(CertificateRequest)
  }
}

class CertificateRequest extends HandshakeState {
  handleCertificateRequest (data) {
    const unshift = size => K(data.slice(0, size))(data = data.slice(size))

    if (data.length < 1 || data[0] + 1 > data.length) throw new Error('invalid length')
    this.hs.certificateTypes = Array.from(unshift(unshift(1)[0]))

    if (data.length < 2 ||
      data.readUInt16BE() % 2 ||
      data.readUInt16BE() + 2 > data.length) {
      throw new Error('invalid length')
    }

    this.hs.signatureAlgorithms = Array
      .from(unshift(unshift(2).readUInt16BE()))
      .reduce((acc, c, i, arr) =>
        (i % 2) ? [...acc, arr[i - 1] * 256 + c] : acc, [])

    // ignore distinguished names

    this.setState(ServerHelloDone)
  }
}

class ServerHelloDone extends HandshakeState {
  handleServerHelloDone (data) {
    if (data.length) throw new Error('invalid server hello done')
    // certificate
    this.write(CERTIFICATE, Prepend24(Buffer.concat([
      ...this.ctx.getClientCertificates().map(c => Prepend24(c))])))
    // key exchange
    this.write(CLIENT_KEY_EXCHANGE, Prepend16(crypto.publicEncrypt({
      key: this.hs.serverPublicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING
    }, this.hs.preMasterSecret)))
    // sign tbs to prove client has private key
    this.ctx.certificateVerify(this.hs.tbs())
    this.setState(CertificateVerify)
  }
}

class CertificateVerify extends HandshakeState {
  certificateVerified (algorithm, signature) {
    this.write(CERTIFICATE_VERIFY, Buffer.concat([algorithm, Prepend16(signature)]))
    this.changeCipherSpec()

    console.log('this.hs.clientVerifyData()', this.hs.clientVerifyData())

    this.write(FINISHED, this.hs.clientVerifyData())
    this.setState(ChangeCipherSpec)
  }
}

class ChangeCipherSpec extends HandshakeState {
  handleChangeCipherSpec () {
    this.serverChangeCipherSpec()
    this.setState(ServerFinished)
  }
}

class ServerFinished extends HandshakeState {
  handleFinished (data) {
    if (!data.equals(this.hs.serverVerifyData())) {
      throw new Error('verify data mismatch')
    }
    this.setState(Established)
  }
}

class Established extends State {
  handleApplicationData (data) {
    console.log('app data', data)
  }
}

// thin wrapper for state machine
class TLS extends Duplex {
  constructor (socket, opts) {
    super()
    this.opts = opts
    this.finished = false

    this.socket = socket
    this.data = Buffer.alloc(0)
    this.fragment = Buffer.alloc(0)
    this.fragmentType = 255
    this.cipher = null
    this.decipher = null

    try {
      const onData = data => {
        try {
          this.handleSocketData(data)
        } catch (e) {
          console.log(e)
        }
      }

      const onError = err => {
      }

      const onClose = () => {
      }

      socket.on('data', onData)
      socket.on('error', onError)
      socket.on('close', onClose)

      this.state = new ServerHello(this)
    } catch (e) {
      console.log(e)
    }
  }

  // fragment is plain text
  handleFragment (type, fragment) {
    if (this.fragment.length) {
      if (this.fragmentType !== type) throw new Error('fragment type mismatch')
      this.fragment = Buffer.concat([this.fragment, fragment])
    } else {
      this.fragment = fragment
      this.fragmentType = type
    }

    const unshift = size => {
      let data = this.fragment.slice(0, size)
      this.fragment = this.fragment.slice(size)
      return data
    }

    while (this.fragment.length) {
      switch (type) {
        case 20: { // change cipher spec
          if (this.fragment[0] !== 1) throw new Error('bad change ciper spec')
          this.state.handleChangeCiperSpec(unshift(1))
          break
        }
        case 21: { // alert
          if (this.fragment.length < 2) return
          this.state.handleAlert(unshift(2))
          break
        }
        case 22: { // handshake, pass complete message, with header
          if (this.fragment.length < 4) return
          let length = this.fragment.readUInt32BE() & 0xffffff
          if (this.fragment.length < 4 + length) return
          this.state.handleHandshake(unshift(4 + length))
          break
        }
        case 23: { // application data
          this.state.handleApplicationData(unshift(this.fragment.length))
          break
        }
        default: {
          throw new Error('exception')
        }
      }
    }
  }

  handleSocketData (data) {
    this.data = Buffer.concat([this.data, data])
    while (this.data.length >= 5) {
      let type = this.data[0]
      if (type < 20 || type > 23) throw new Error('unknown content type')
      let version = this.data.readUInt16BE(1)
      if (version !== 0x0303) throw new Error('unsupported protocol version')
      let length = this.data.readUInt16BE(3)
      if (this.data.length < 5 + length) break
      let fragment = this.data.slice(5, 5 + length)
      this.data = this.data.slice(5 + length)
      if (this.deciper) fragment = this.decipher(fragment)
      this.handleFragment(type, fragment)
    }
  }

  write (type, data) {
    if (this.cipher) data = this.cipher(data)
    data = Buffer.concat([Buffer.from([type]), TLSVersion, Prepend16(data)])
    this.socket.write(data)
  }

  certificateVerify (tbs) {
    fs.readFile('deviceCert.key', (err, key) => {
      if (err) throw err
      let algorithm = Buffer.from([0x04, 0x01])
      let signature = crypto.createSign('sha256').update(tbs).sign(key)
      this.state.certificateVerified(algorithm, signature)
    })
  }

  createCipher (key, macKey, counter) {
    let sn = createSequenceNumber()

    this.cipher = (type, data) => {
      let iv = crypto
        .createHash('sha256')
        .update((++counter).toString())
        .digest()
        .slice(0, 16)
      let cipher = crypto
        .createCipheriv('aes-128-cbc', key, iv)
        .setAutoPadding(false)

      let tbs = Buffer.concat([sn(), UInt8(type), TLSVersion, Prepend16(data)])
      let mac = crypto.createHmac('sha1', macKey).update(tbs).digest()
      let padNum = 16 - (data.length + mac.length) % 16
      let padding = Buffer.alloc(padNum, padNum - 1)
      return Buffer.concat([
        iv,
        cipher.update(Buffer.concat([data, mac, padding])),
        cipher.final()
      ])
    }

    this.cipher.sn = sn
  }

  createDecipher (key, macKey) {
    let sn = createSequenceNumber()

    this.decipher = (type, data) => {
      let iv = data.slice(0, 16)
      let decipher = crypto.createDecipheriv('aes-128-cbc', key, iv)
      decipher.setAutoPadding(false)

      let padded = Buffer.concat([decipher.update(data.slice(16)), decipher.final()])
      let padNum = padded[padded.length - 1] + 1
      if (padded.length < padNum) throw new Error('bad padding')

      let padding = padded.slice(padded.length - padNum)
      if (!padding.equals(Buffer.alloc(padNum, padNum - 1))) {
        throw new Error('bad padding')
      }

      let dec = padded.slice(0, padded.length - padNum - 20)
      let smac = padded.slice(padded.length - padNum - 20, padded.length - padNum)
      let cmac = crypto.createHmac('sha1', macKey)
        .update(Buffer.concat([sn(), UInt8(type), TLSVersion, Prepend16(dec)]))
        .digest()

      if (!smac.equals(cmac)) throw new Error('mac mismatch')

      return dec
    }

    this.decipher.sn = sn
  }

  getClientCertificates () {
    return this.opts.clientCertificates
  }

  _write (...args) {
    this.state._write(...args)
  }

  _read (size) {
    this.state._read(size)
  }

  static createConnection (opts, callback) {
    const socket = new net.Socket()
      .once('error', err => {
        socket.removeAllListeners('connect').on('error', () => {})
        callback(err)
      })
      .once('connect', () => {
        socket.removeAllListeners('error')
        const tls = new TLS(socket, opts)
          .once('error', err => {
            tls.removeAllListeners('connect').on('error', () => {})
            callback(err)
          })
          .once('connect', () => {
            tls.removeAllListeners('error')
            callback(null, tls)
          })
      })
      .connect(opts.port, opts.host)
  }
}

TLS.createConnection({
  port: 8883,
  host: 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn',
  // certs must be DER format
  clientCertificates: [
    Buffer.from(fs.readFileSync('deviceCert.crt')
      .toString()
      .split('\n')
      .filter(x => !!x && !x.startsWith('--'))
      .join(''), 'base64')
  ],
  // key is PEM format
  clientPrivateKey: fs.readFileSync('deviceCert.key')
}, (err, connection) => {
  console.log('tls connected')
})
