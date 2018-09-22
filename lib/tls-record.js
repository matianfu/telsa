const crypto = require('crypto')
const { Duplex } = require('stream')

const {
  K,
  UInt8, UInt16, UInt24, readUInt24,
  Prepend8, Prepend16, Prepend24, 
  TLSVersion, 
  AES_128_CBC_SHA
} = require('./common')
 

/**
  struct {
      uint8 major;
      uint8 minor;
  } ProtocolVersion;

  enum {
      change_cipher_spec(20), alert(21), handshake(22),
      application_data(23), (255)
  } ContentType;

  struct {
      ContentType type;
      ProtocolVersion version;
      uint16 length;
      opaque fragment[TLSPlaintext.length];
  } TLSPlaintext;
*/

const ContentTypes = [20, 21, 22, 23]

class Outgoing extends Duplex {

  constructor() {
    super({ writableObjectMode: true })
    this.buffer = Buffer.alloc(0)
    this.sn = 0
    this.macKey = null
    this.key = null 
    this.macKeyCandidate = null
    this.keyCandidate = null
  }

  _write (msg, _, callback) {
    let { type, data } = msg
  
    if (this.secure) {
      let sn = this.sn++
      let tbs = Buffer.concat([sn, UInt8(type), TLSVersion, Prepand16(data)])
      let mac = crypto.createHmac('sha1', this.macKey).update(tbs).digest()
      let padding = 16 - (msg.data.length + mac.length) % 16
      let plain = Buffer.concat([data, mac, Buffer.alloc(padding, padding - 1)]) 
      let cipher = crypto.createCipheriv('aes-128-cbc', this.key, iv)
        .setAutoPadding(false)
      data = Buffer.concat([iv, cipher.update(plain), cipher.final()])
    } 

    this.buffer = Buffer.concat([
      this.buffer,
      Buffer.from([type]), 
      TLSVersion, 
      Prepend16(data)
    ])

    callback(null)
  }

  _read (size) {
    this.push(this.buffer)
    this.buffer = Buffer.alloc(0)
  }
}

class Incoming extends Duplex {

  constructor () {
    super({ readableObjectMode: true })

    this.data = Buffer.alloc(0)
    this.fragment = null

    this.sn = 0
    this.macKey = null
    this.key = null

    this.macKeyCandidate = null
    this.keyCandidaate = null
  }

  handleFragment (type, data) {
    const unshift = size => {
      let x = this.fragment.data.slice(0, size)
      this.fragment.data = this.fragment.data.slice(size)
      return x
    }

    if (this.fragment) {
      if (type !== this.fragment.type) throw new Error('fragemnt type mismatch')
      this.fragment.data = Buffer.concat([this.fragment.data, data])
    } else {
      this.fragment = { type, data }
    }

    while (this.fragment.data.length) {
      switch (type) {
        case 20: {  // change cipher spec
          // TODO
          console.log('before push')
          this.push({ type, data: unshift(1) })
          break
        }
        case 21: {  // alert
          if (this.fragement.data.length < 2) return
          this.push({ type, data: unshift(2)})
          break
        }

        case 22: { // handshake
          console.log(this.fragment.data.length)
          if (this.fragment.data.length < 4) return
          let length = this.fragment.data.readUInt32BE() & 0xffffff
          if (this.fragment.data.length < 4 + length) return
          this.push({ type, data: unshift(4 + length) })
          break
        }

        case 23: { // application data
          this.push({ type, data: unshift(this.fragment.data.length) })
          break
        }

        default:
          throw new Error('bad type')
      }
    }

    this.fragment = null
  }

  _write (data, _, callback) {
    this.data = Buffer.concat([this.data, data])

    while (this.data.length >= 5) {
      let type = this.data[0]
      let version = this.data.readUInt16BE(1)
      let length = this.data.readUInt16BE(3)
      if (this.data.length < 5 + length) break
      let fragment = this.data.slice(5, 5 + length)
      this.data = this.data.slice(5 + length)
      this.handleFragment (type, fragment)
    }
  }

  _read (size) {
  }
}

module.exports = { Incoming, Outgoing }


