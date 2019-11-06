const stream = require('stream')

class D extends stream.Duplex {
  constructor (opts) {
    super(opts)
    this.closing = false
    this.writeCb = null
  }

  _close (error) {
    this.closing = true

    if (this.writeCb) {
      console.log('before deferred callback')
      this.writeCb(error)
      console.log('after deferred callback')
    } 

    console.log('before push null')
    this.push(null)
    console.log('after push null')

    console.log('before end')
    this.end()
    console.log('after end')

    process.nextTick(() => this.emit('close', error))
  }

  _write (chunk, encoding, callback) {
    console.log('_write', this.closing)
    if (this.closing) {
      callback()
    } else {
      this.writeCb = callback
      setImmediate(() => this._close())
    }
  }

  _final (callback) {
    console.log('_final')
    callback()
  }

  _read (size) {
  } 

  _destroy (err, callback) {
    console.log('_destroy', err)
    callback()
  }
}

const d = new D()
d.on('error', err => {
  console.log(err)
  d.end()
})

d.on('finish', () => console.log('finish'))
d.on('data', () => console.log('data'))
d.on('end', () => console.log('end'))
d.on('drain', () => console.log('drain'))
d.on('close', () => console.log('close'))
d.write(Buffer.alloc(16384))
d.write(Buffer.alloc(16384))
d.write(Buffer.alloc(16384))
d.end(() => console.log('end listener'))

setTimeout(() => {}, 5000)
