const child = require('child_process')
const Socket = require('net').Socket
const Duplex = require('stream').Duplex
const Transport = require('./transport')

class Context extends Duplex {
  constructor (opts) {
    super(opts)
    this.opts = opts
    this.socket = null

    this.pushable = true

    this.socketWritable = true

    this.writeCb = null
    this.finalCb = null
  }

  verifyServerCertificates (certs, callback) {
    let ca = this.opts.ca
    // convert DER to PEM
    let pems = certs
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
        callback(err)
      } else if (token === 'stdin: OK') {
        callback(null, true)
      } else {
        callback(null, false)
      }
    })
    this.openssl.stdin.write(cert)
    this.openssl.stdin.end()
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
    while (this.socketWritable && this.transport.outgoing.length) {
      let data = this.transport.outgoing.shift()
      console.log('outgoing ->', data)
      this.socketWritable = this.socket.write(data)
    } 

    if (this.socketWritable) {
      if (this.writeCb) {
        let cb = this.writeCb
        this.writeCb = null
        cb()
      } 
      if (this.finalCb) {
        this.socket.end()
        let cb = this.finalCb
        this.finalCb = null
        cb()
      }
    }
  }

  _write (chunk, encoding, callback) {
    this.writeCb = callback
    this.transport.write(chunk)
  }

  _final (callback) {
    this.finalCb = callback
    this.transport.write(null)
  }

  _read (size) {
    this.pushable = true
    this.drainIncoming() 
  }

  connect (port, host, listener) {
    let socket = new Socket()
    socket.on('close', () => {
      console.log('socket close')
      this.emit('close')
    })

    socket.on('end', () => {
      console.log('socket end')
      this.push(null)
      this.end()
    })

    socket.on('finish', () => console.log('socket finish')) 
    socket.on('error', err => this.emit(err))
    socket.on('readable', () => this.drainIncoming())
    socket.on('drain', () => {
      this.socketWritable = true
      this.drainOutgoing()
    })
    socket.connect(port, host, () => {
      let opts = Object.assign({}, this.opts, {
        verifyServerCertificates: this.verifyServerCertificates.bind(this)
      }) 

      this.transport = new Transport(opts)
      this.transport.on('established', () => this.emit('connect'))
      this.transport.on('outgoing', () => this.drainOutgoing())
    })

    this.socket = socket
    if (listener) this.on('connect', () => listener())
  }
} 

module.exports = Context
