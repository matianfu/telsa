const { Duplex } = require('stream')
const net = require('net')
const crypto = require('crypto')

const {
  ClientHello,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest
} = require('./handshake')

class State {
  constructor (ctx, socket) {
    if (ctx instanceof State) {
      this.ctx = ctx.ctx    
      this.socket = ctx.socket
      this.data = ctx.data
      this.fragment = ctx.fragment
      this.fragmentType = ctx.fragmentType
    } else {
      this.ctx = ctx
      this.socket = socket
      this.data = Buffer.alloc(0)
      this.fragment = Buffer.alloc(0)
      this.fragmentType = 255 // invalid value
    }
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
    let enc = this.ctx.encryption
    if (enc) {
      let sn = enc.sn++
      let tbs = Buffer.concat([sn, UInt8(type), TLSVersion, Prepend16(data)])
      let mac = crypto
    } 
  }

  handleChangeCiperSpec () { }
  handleAlert () { }
  handleHandshake (data) { }
  handleAppData (data) { }

  handleFragment (type, fragment) {
    let c = this.ctx
    if (c.fragment.length) {
      if (c.fragmentType !== type) throw new Error('fragment type mismatch')
      c.fragment = Buffer.concat([c.fragment, fragment])
    } else {
      c.fragment = fragment
      c.fragmentType = type
    }

    while (c.fragment.length) {
      switch (type) {
        case 20: {  // change cipher spec
          if (c.fragment[0] !== 1) throw new Error('bad change ciper spec message')
          this.handleChangeCiperSpec()
          c.fragment = c.fragment.slice(1)
          break
        }
        case 21: {  // alert
          if (c.fragment.length < 2) return // incomplete 
          this.handleAlert(c.fragment.slice(0, 2))
          c.fragment = c.fragment.slice(2)
          break
        }
        case 22: {  // handshake
          if (c.fragment.length < 4) return // incomplete
          let length = c.fragment.readUInt32BE() & 0xffffff
          if (c.fragment.length < 4 + length) return // incomplete
          this.handleHandshake(c.fragment.slice(0, 4 + length))
          c.fragment = c.fragment.slice(4 + length)
          break
        }
        case 23: {  // application data
          this.handleAppData(c.fragment.slice(0, c.fragment.length))
          c.fragment = c.fragment.slice(c.fragment.length)
          break
        }
        default: {
          throw new Error('exception')
        }
      }
    }
  }

  handleSocketData (data) {
    let c = this.ctx 
    c.data = Buffer.concat([c.data, data])

    while (c.data.length >= 5) {
      if (c.data[0] < 20 || c.data[0] > 23) 
        throw new Error('unknown content type')
      if (c.data.readUInt16BE(1) !== 0x0303) 
        throw new Error('unsupported protocol version')

      let length = c.data.readUInt16BE(3)
      if (c.data.length < 5 + length) break

      this.handleFragment(c.data[0], c.data.slice(5, 5 + length))
      c.data = c.data(slice + length)
    }
  }

  tryHandleSocketData (data) {
    try {
      this.handleSocketData(data)
    } catch (e) {
      this.setState(Failed)
    }
  }
}

// this is a super state
class HandshakeState extends State {
  constructor (ctx) {
    super(ctx)
    if (ctx instanceof HandshakeState) {
      this.hs = ctx.hs
    } else {
      // prepare handshake context
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
        masterSecret,
      }
    }
  }

  write (data) {
    this.hs.buffer.push(super.write(data))
  }
}

class ServerHello extends HandshakeState {
  enter () {
    this.ctx.startHandshake()
    let msg = ClientHelloMessage(this.ctx.clientRandom)
    this.write(22, msg)
  }

  handleHandshake (msg) {
    if (type !== 2) throw new Error('not a server hello message')
    this.ctx.handshakeMessages.push(msg)
    let { random, sessionId } = handleServerHello(body)  
    this.ctx.serverRandom = random
    this.ctx.sessionId = sessionId
    this.setState(ServerCertificate)
  }
}

class ServerCertificate extends State {
  handleHandshake (type, data) {
    if (type !== 11) throw new Error('not a server cerificate message')
    this.ctx.handshakeMessages.push(msg.data)
    let r = handleServerCertificate(msg.data.slice(4))
    this.ctx.serverPublicKey = r.publicKey
    this.ctx.serverCertificates = r.certs
    this.setState(CertificateRequest)
  } 
}

class CertificateRequest extends State {
  handleHandshake (type, data) {
    if (type !== 13) throw new Error('not a certificate request message')

    this.ctx.handshakeMessages.push(msg.data)
    let r = handleCertificateRequest(msg.data.slice(4))
    let data = ClientCertificate(this.ctx.clientCertificates)
    this.ctx.handshakeMessages.push(data)
    this.write({ type: 22, data })   

    this.ctx.preMasterSecret = Buffer.alloc(48) 
    cyrpto.randomFillSync(this.ctx.preMasterSecret)
    preMasterSecret[0] = 0x03
    preMasterSecret[1] = 0x03
    data = ClientKeyExchange(this.ctx.serverPublicKey, preMasterSecret)
    this.ctx.handshakeMessages.push(data)
    this.write({ type: 22, data })

    let tbs = Buffer.concat(this.ctx.handshakeMessages)
    let key = fs.readFileSync('deviceCert.key')
    data = CertificateVerify(key, tbs)
    this.ctx.handshakeMessages.push(data)
    this.write({ type: 22, data })

    // change cipher spec
    this.write({ type: 20,  })
    this.reader.expectChangeCipherSpec({})
  }
}

class Established extends State {
  handleMessage (msg) {
  }
} 

class Failed extends State {
  handleMessage (msg) {
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
   
    let padded = Buffer.concat([decipher.update(encrypted.slice(16)), decipher.final())
    
    let padNum = padded[padded.length - 1] + 1
    if (padded.length < padNum) throw new Error('invalid padding')
    if (!padded.slice(padded.length - padNum).equals(Buffer.alloc(padNum, padNum - 1))
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
      .map(x => Buffer.alloc(4).writeUInt32BE(x)))

    return crypto.createHash('sha256')
      .update(Buffer.concat(brr))
      .digest()
      .slice(0, 16)
  }
}

// thin wrapper for state machine
class TLS extends Duplex {
  constructor (socket) {
    super()
    this.state = new ClientHello(this, socket)
  }

  _write (...args) {
    this.state._write(...args) 
  }

  _read (size) { 
    this.state._read(...args)
  }

  static createConnection (port, host, callback) {
    let socket = new net.Socket()
    socket.once('error', function onError (err) {
      socket.removeListener('connect', onConnect) 
      socket.on('error', () => {})
      callback(err)
    })
    socket.once('connect', function onConnect () {
      socket.removeListener('error', onError) 
      callback(null, new TLS(socket))
    })
  }
}

let tls = TLS.createConnection(8883, 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn')

