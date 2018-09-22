const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')

const {
  ClientHelloMessage,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest
  ClientCertificate,
  ClientKeyExchange
} = require('./handshake')

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
const HS_HELLO_REQUEST = 0
const HS_CLIENT_HELLO = 1
const HS_SERVER_HELLO = 2
const HS_CERTIFICATE = 11
const HS_SERVER_KEY_EXCHANGE = 12
const HS_CERTIFICATE_REQUEST = 13
const HS_SERVER_HELLO_DON = 14
const HS_CERTIFICATE_VERIFY = 15
const HS_CLIENT_KEY_EXCHANGE = 16
const HS_FINISHED = 20

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

const TLSRecord = (type, data) => Buffer.concat([
  Buffer.from([type]),
  TLSVersion,
  Prepend16(data)
])


// the base state has the same life cycle with the underlying socket
class State {
  constructor (ctx) {
    this.ctx = (ctx instanceof State) ? ctx.ctx : ctx
  }

  exit () { }

  setState (NextState, ...args) {
    for (let p = this.__proto__; 
      !(NextState.prototype instanceof p.constructor); 
      p.hasOwnProperty('exit') && p.exit.apply(this),
      p = p.__proto__);

    this.ctx.state = new NextState(this, ...args)
  }

  write (type, data) {
    this.ctx.write(type, data)
  }

  handleChangeCiperSpec (data) { }

  handleAlert (data) { }

  handleHandshake (data) { 
    console.log('handleHandshake', data)
  }

  handleAppData (data) { 

  }
}

// this is a super state
class HandshakeState extends State {
  constructor (ctx) {
    super(ctx)
    if (ctx instanceof HandshakeState) {
      this.hs = ctx.hs
      console.log('Handshake migrated')
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
        serverRandom: null,
        preMasterSecret,
        masterSecret: null,

        tbs () {
          return Buffer.concat(this.buffer)
        },

        digest () {
          return crypto.createHash('sha256').update(this.tbs()).digest()
        }
      }
    }
  }

  write (type, data) {
    super.write(type, data)
    if (type === HANDSHAKE) this.hs.buffer.push(data)
  }

  handleHandshake (data) {
    if (data[0] === HS_HELLO_REQUEST) return true
    this.hs.buffer.push(data)
  }
}

class ServerHello extends HandshakeState {
  constructor(ctx) {
    super(ctx)
    this.write(HANDSHAKE, ClientHelloMessage(this.hs.clientRandom))
  }

  handleHandshake (data) {
    if (super.handleHandshake(data)) return
    if (data[0] !== HS_SERVER_HELLO) 
      throw new Error('not a server hello message')
    let { random, sessionId } = handleServerHello(data.slice(4))  
    this.hs.serverRandom = random
    this.hs.sessionId = sessionId
    this.setState(ServerCertificate)
  }
}

class ServerCertificate extends HandshakeState {
  handleHandshake (data) {
    if (super.handleHandshake(data)) return
    if (data[0] !== HS_CERTIFICATE) 
      throw new Error('not a server cerificate message')
    let r = handleServerCertificate(data.slice(4))
    this.hs.serverPublicKey = r.publicKey
    this.hs.serverCertificates = r.certs
    this.setState(CertificateRequest)
  } 
}

class CertificateRequest extends HandshakeState {
  handleHandshake (data) {
    if (super.handleHandshake(data)) return
    if (data[0] !== HS_CERTIFICATE_REQUEST) 
      throw new Error('not a certificate request message')

    handleCertificateRequest(data.slice(4))

    this.write(HANDSHAKE, 
      ClientCertificate(this.hs.clientCertificates))

    this.write(HANDSHAKE, 
      ClientKeyExchange(this.hs.serverPublicKey, this.hs.preMasterSecret))

    this.ctx.certificateVerify(this.hs.tbs())
    this.setState(CertificateVerify) 
 
/**
    let key = fs.readFileSync('deviceCert.key')
    this.write(HANDSHAKE, 
      CertificateVerify(this.hs.key, this.hs.tbs()))
*/
    
    // change cipher spec
    // this.write({ type: 20,  })
    // this.reader.expectChangeCipherSpec({})
  }
}

class CertificateVerify extends HandshakeState {
  certificateVerified (algorithm, signature) {
    this.write(HANDSHAKE, Buffer.concat([algorithm, Prepend16(signature)]))
    this.write(CHANGE_CIPHER_SPEC, Buffer.from([1]))
    this.ctx.createCipher()
    this.setState(ChangeCipherSpec)
  }
}

class ChangeCipherSpec extends HandshakeState {
  handleChangeCipherSpec () {
    this.ctx.createDecipher()
    this.setState(HandshakeFinished)
  }
}

class HandshakeFinished extends HandshakeState {
  handleHanshake () {
    this.setState(Established)
  }
}

class Established extends State {
  handleApplicationData (data) {
    console.log('app data', data)
  }
} 

class Cipher {
  construct () {
    this.seed = seed
  }

  encrypt (type, data) {
    let iv = this.iv()
    let cipher = crypto.createCipheriv('aec-128-cbc', this.key, iv)
    cipher.setAutoPadding(false)

    let tbs = Buffer.concat([this.sn++, UInt8(type), TLSVersion, Prepend16(data)]) 
    let mac = crypto.createHmac('sha1', this.macKey).update(tbs).digest()
    let padNum = 16 - (msg.data.length + mac.length) % 16
    let padding = Buffer.alloc(padNum, padNum - 1)
    let encrypted = cipher.update(Buffer.concat([data, mac, padding]))
    // TODO
    return Buffer.concat([iv, encrypted])
  }

  decrypt (encrypted) {
    let iv = this.iv()
    let decipher = crypto.createDecipheriv('aes-128-cbc', this.key, iv)
    decipher.setAutoPadding(false)
   
    let padded = Buffer.concat([decipher.update(encrypted.slice(16)), decipher.final()])
    
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

  // iv is a sha256 hash of a random number (0 - 2 ^ (16 * 8))
  iv () {
    let iv = this.seed++
    let brr = [iv, iv >> 8, iv >> 16, iv >> 32]
      .map(x => Buffer.alloc(4).writeUInt32BE(x))

    return crypto.createHash('sha256')
      .update(Buffer.concat(brr))
      .digest()
      .slice(0, 16)
  }
}

// thin wrapper for state machine
class TLS extends Duplex {
  constructor (socket, opts) {
    super()

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
        case 20: {  // change cipher spec
          if (this.fragment[0] !== 1) throw new Error('bad change ciper spec')
          this.state.handleChangeCiperSpec(unshift(1))
          break
        }
        case 21: {  // alert
          if (this.fragment.length < 2) return
          this.state.handleAlert(unshift(2))
          break
        }
        case 22: {  // handshake, pass complete message, with header
          if (this.fragment.length < 4) return 
          let length = this.fragment.readUInt32BE() & 0xffffff
          if (this.fragment.length < 4 + length) return
          this.state.handleHandshake(unshift(4 + length))
          break
        }
        case 23: {  // application data
          this.state.handleAppData(unshift(this.fragment.length))
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
    this.socket.write(TLSRecord(type, data))
  }

  _write (...args) {
    this.state._write(...args) 
  }

  _read (size) { 
    this.state._read(...args)
  }

  static createConnection (port, host, callback) {
    const socket = new net.Socket()
      .once('error', err => {
        socket.removeAllListeners('connect').on('error', () => {})
        callback(err) 
      })
      .once('connect', () => {
        socket.removeAllListeners('error') 
        const tls = new TLS(socket)
          .once('error', err => {
            tls.removeAllListeners('connect').on('error', () => {})
            callback(err)
          })
          .once('connect', () => {
            tls.removeAllListeners('error')
            callback(null, tls)
          })
      })
      .connect(port, host)
  }
}

let port = 8883
let host = 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn'

TLS.createConnection(port, host, (err, connection) => {
  console.log('tls connected')
})

