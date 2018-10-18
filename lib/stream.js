const Socket = require('net').Socket
const Duplex = require('stream').Duplex
const Transport = require('./transport')

class Context extends Duplex {
  constructor (opts) {
    super(opts)
    this.opts = opts
    this.verifier =  
    this.socket = null

    this.pushable = true
    this.writable = true

    this.writeCb = null
    this.finalCb = null
  }

  drainIncoming () {
    if (this.pushable) {
      this.transport.receive(this.socket.read())
      while (this.pushable && this.transport.incoming.length) {
        this.pushable = this.push(this.transport.incoming.shift())
      }
    }
  }

  drainOutgoing () {
    while (this.writable && this.transport.outgoing.length) {
      this.writable = this.socket.write(this.transport.outgoing.shift())
    } 

    if (this.writable) {
      if (this.writeCb) {
        let cb = this.writeCb
        this.writeCb = null
        cb()
      } 
      if (this.finalCb) {
        let cb = this.finalCb
        this.finalCb = null
        cb()
      }
    }
  }

  _write (chunk, encoding, callback) {
    this.writeCb = callback
    this.transport.write(chunk)
    this.drainOutgoing()
  }

  _final (callback) {
    this.finalCb = callback
    this.drainOutgoing()
  }

  _read (size) {
    this.pushable = true
    this.drainIncoming() 
  }

  connect (port, host, listener) {
    let socket = new Socket()
    socket.on('error', err => this.emit(err))
    socket.on('readable', () => this.drainIncoming())
    socket.on('drain', () => this.drainOutgoing())
    socket.connect(port, host, () => {
      this.transport = new Transport(this.opts)
      this.transport.on('established', () => this.emit('connect'))
      this.transport.on('outgoing', () => this.drainOutgoing())
      this.drainOutgoing()
    })

    this.socket = socket

    if (listener) this.on('connect', () => listener())
  }
} 

module.exports = Context
