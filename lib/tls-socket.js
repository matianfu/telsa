const { Readable, Writable, Duplex, Transform } = require('stream')


class TLSEncoder extends Transform {

  constructor() {
    super()
    this.buffer = Buffer.alloc(0)
  }

  _transform (chunk, encoding, callback) {
    this.buffer = Buffer.concat([this.buffer, buffer])
  }
}


class TLSConnection extends Duplex {

  constructor (socket, options) {
    super ()  

    this.sp = {

    }

    this.incoming = new Transfrom({
    }) 

  }

  _write () {
  }

  _read () {
  }
}
