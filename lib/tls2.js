const path = require('path')
const fs = require('fs')
const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')

const {
  ClientHelloMessage,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest,
  ClientCertificate,
  ClientKeyExchange,
  deriveKeys,
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

const createSequenceNumber = () => {
  let buf = Buffer.alloc(8)

  const read = () => {
    let r = Buffer.slice(0)
    buf.writeUInt32BE(buf.readUInt32BE(4) + 1, 4) 
    if (buf.readUInt32BE(4) === 0) {
      buf.writeUInt32BE(buf.readUInt32BE(0) + 1, 0)
      if (buf.readUInt32BE(0) === 0)
      throw new Error('sequence number overflow')
    }
    return r
  }

  read.peek = () => buf
  return read
}

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

  handleChangeCiperSpec (data) { 
    throw new Error('unexpected change cipher spec')
  }

  handleAlert (data) { 
    
  }

  handleHandshake (data) { 
    console.log('handleHandshake', data)
  }

  handleApplicationData (data) { 

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
        },

        derive () {
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
            .map(n => BigInt(n))
            .reduce((sum, c, i) => (sum + c << (8n * BigInt(i))), 0n)
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
    let hs = this.hs
    this.write(HANDSHAKE, ClientCertificate(hs.clientCertificates))
    this.write(HANDSHAKE, ClientKeyExchange(hs.serverPublicKey, hs.preMasterSecret))
    // expect exteranl signature
    this.ctx.certificateVerify(hs.tbs())
    this.setState(CertificateVerify) 
  }
}

class CertificateVerify extends HandshakeState {
  certificateVerified (algorithm, signature) {
    // certificate verify
    this.write(HANDSHAKE, Buffer.concat([algorithm, Prepend16(signature)]))
    this.write(CHANGE_CIPHER_SPEC, Buffer.from([1]))
    let hs = this.hs
    hs.deriveKeys()
    this.ctx.createCipher(hs.clientWriteKey, hs.clientWriteMacKey, hs.iv)
    // expect server change cipher spec
    this.setState(ChangeCipherSpec)
  }

  handleHandshake (data) {
    if (super.handleHandshake(data)) return
    throw new Error('invalid handshake message')
  }
}

class ChangeCipherSpec extends HandshakeState {
  handleChangeCipherSpec () {
    this.ctx.createDecipher(this.hs.serverWriteKey, this.hs.serverWriteMacKey)
    // expect server handshake finished
    this.setState(HandshakeFinished)
  }

  handleHandshake (data) {
    if (super.handleHandshake(data)) return
    throw new Error('invalid handshake message')
  }
}

class HandshakeFinished extends HandshakeState {
  handleHanshake (data) {
    if (super.handHandshake(data)) return
    // handle handshake finished
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
    this.socket.write(TLSRecord(type, data))
  }

  certificateVerify (tbs) {
    fs.readFile('./deviceCert.key', (err, key) => {
      if (err) throw err
      let algorithm = Buffer.from([0x04, 0x01])
      let signature = crypto.createSign('sha256').update(tbs).sign(key)
      this.state.certificateVerified(algorithm, signature)
    })
  }

  createCipher (key, macKey, counter) {
    let sn = createSequenceNumber()

    this.cipher = (type, data) => {
      let iv = crypto.createHash('sha256')
        .update((++counter).toString())
        .digest()
        .slice(0, 16)
      let cipher = crypto.createCipheriv('aes-128-cbc', key, iv)  
      cipher.setAutoPadding(false)

      let tbs = Buffer.concat([sn(), UInt8(type), TLSVersion, Prepend16(data)]) 
      let mac = crypto.createHmac('sha1', mackey).update(tbs).digest()
      let padNum = 16 - (msg.data.length + mac.length) % 16
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
      if (padded.length < padNum) 
        throw new Error('bad padding')

      let padding = padded.slice(padded.length - padNum)
      if (!padding.equals(Buffer.alloc(padNum, padNum - 1)))  
        throw new Error('bad padding')

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

