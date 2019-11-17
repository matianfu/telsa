const path = require('path')
const chai = require('chai')
const expect = chai.expect

const EventEmitter = require('events')
const Telsa = require('../src/telsa')

class T extends Telsa {

  constructor (opts) {
    super(opts)
    this.t = {}
  }

  emit (err) {
  }

  push (something) {
  }
}

class Mocket extends EventEmitter {
  constructor () {
    super()
    this.ended = 0
  }

  end () {
    this.ended++ 
  }
}

describe(path.basename(__filename), () => {
  it('should do something', done => {
    const socket = new Mocket()
    const tls = new T({ socket })
    let cb = 0
    tls._final(() => {
      cb++
    })

    expect(tls.writing).to.be.null
    expect(tls.state).to.equal('Terminated')

    done()
  })
})

