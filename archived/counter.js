const fs = require('fs')
const { Readable } = require('stream');

class Counter extends Readable {
  constructor(opt) {
    super(opt);
    this._max = 1000000;
    this._index = 1;
  }

  _read() {
    const i = this._index++;
    if (i === 200000) {
      this.emit('error', new Error('i is 2'))
    } else if (i > this._max) {
      this.push(null);
    } else {
      const str = String(i);
      const buf = Buffer.from(str, 'ascii');
      this.push(buf);
    }
  }
}

const ws = fs.createWriteStream('tmptest')

let c = new Counter()
c.on('error', err => {
  console.log(err)
  c.unpipe()
  ws.end()
})
c.pipe(ws)

setTimeout(() => {}, 3000)
