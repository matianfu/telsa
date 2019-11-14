const { ContentType } = require('./common')
const { CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA } = ContentType

const Defragger = require('./defragger')

/**
 * Reader
 */
class Reader {
  /**
   * construct a reader
   */
  constructor () {
    this.defragger = new Defragger()
    this.frag = null
  }

  /**
   * concat fragments
   */
  appendFrag (frag) {
    if (this.frag) {
      if (frag.type !== this.frag.type) {
        throw new Error('fragment type mismatch')
      }
      this.frag.data = Buffer.concat([this.frag.data, frag.data])
    } else {
      this.frag = frag
    }
  }

  /**

  */
  slice (size) {
    if (!this.frag) throw new Error('null frag')
    if (this.frag.data.length < size) throw new Error('inadequate data')

    const slice = this.frag.data.slice(0, size)
    if (size === this.frag.data.length) {
      this.frag = null
    } else {
      this.frag.data = this.frag.data.slice(size)
    }
    return slice
  }

  /**
  append input data
  */
  append (data) {
    this.defragger.append(data)
  }

  /**
   * read a message from current fragment
   */
  readFromFrag () {
    if (!this.frag) return null

    switch (this.frag.type) {
      case CHANGE_CIPHER_SPEC:
        if (this.frag.data[0] !== 1) throw new Error('bad change cipher spec')
        this.slice(1)
        return { type: CHANGE_CIPHER_SPEC }
      case ALERT: {
        if (this.frag.data.length < 2) return null
        const level = this.frag.data[0]
        const description = this.frag.data[1]
        this.slice(2)
        return { type: ALERT, level, description }
      }
      case HANDSHAKE: {
        if (this.frag.data.length < 4) return null
        // TODO validate
        const length = readUInt24(this.frag.data.slice(1))
        // const body =
        return {
          type: HANDSHAKE,
          handshake: {
            type: this.frag.data[0],
            body: null
          }
        }
      }
      case APPLICATION_DATA: {

      } break
      default:
        throw new Error('invalid content type')
    }
  }

  /**
   * set cipher
   */
  setCipher (cipher) {
    this.defragger.setCipher()
  }

  /**
   * read a message
   */
  read () {
    let message
    while (!(message = this.readFromFrag())) {
      const frag = this.defragger.read()
      if (!frag) return null
      this.appendFrag(frag)
    }
    return message
  }
}

module.exports = Reader
