const net = require('net')

class State {
}

class HandshakeState {
}

class TLSSocket extends net.Socket {

  constructor (opts) {
    super(opts)

    this.on('connect', () => {
      this.write(ClientDone())
    })

    
  }

  emit (name, ...args) {
    if (name === 'data') {
      console.log(data)
    } else {
      super.emit(name, ...args)
    }
  }

  write (data) {
  }

} 
