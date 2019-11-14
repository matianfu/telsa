/**
struct {
  ContentType type;         # 1 byte
  ProtocolVersion version;  # 2 bytes
  uint16 length;            # 2 bytes
  opaque fragment[TLSPlaintext.length];
} TLSPlaintext;

struct {
  ContentType type;         # same as TLSPlaintext.type
  ProtocolVersion version;  # same as TLSPlaintext.version
  uint16 length;
  opaque fragment[TLSCompressed.length];
} TLSCompressed;

struct {
  ContentType type;
  ProtocolVersion version;
  uint16 length;
  select (SecurityParameters.cipher_type) {
    case stream: GenericStreamCipher;
    case block:  GenericBlockCipher;
    case aead:   GenericAEADCipher;
  } fragment;
} TLSCiphertext;

length: from 1
  2^14 (plain text),
  2^14 + 1024 (compressed)
  2^14 + 2048 (ciphered)
*/

/**
 * @typedef {Object} Fragment
 * @property {Number} type - content type
 * @property {Buffer} data - fragment data
 */

/**
 * Defragger generates fragments from raw (socket) data
 */
class Defragger {
  /**
   * constructs a defragger
   */
  contructor () {
    /**
     * input buffer
     * @member
     * @type {Buffer}
     */
    this.data = Buffer.alloc(0)

    /**
     * @member
     * @type {Decipher}
     */
    this.decipher = null
  }

  /**
  @return {Number} max content length for plain and ciphered text
  */
  maxLength () {
    if (this.decipher) {
      return Math.pow(2, 14) + 2048
    } else {
      return Math.pow(2, 14)
    }
  }

  /**
  append input data
  */
  append (data) {
    this.data = Buffer.concat([this.data, data])
  }

  /**
  read a fragment out of the data buffer
  @return {Fragment|null}
  */
  read () {
    if (this.data.length < 1) return null
    const type = this.data[0]
    if (type < 20 || type > 23) {
      // TODO add error code in this function
      const err = new Error('bad content type')
      throw err
    }

    if (this.data.length < 3) return null
    const version = this.data.readUInt16BE(1)
    if (version !== 0x0303) {
      const err = new Error('bad protocol version')
      throw err
    }

    if (this.data.length < 5) return null
    const length = this.data.readUInt16BE(3)

    if (length === 0 || length > this.maxLength) {
      const err = new Error('bad content length')
      throw err
    }

    if (this.data.length < 5 + length) return null

    const data = this.data.slice(5, 5 + length)
    this.data = this.data.slice(5 + length)
    return { type, data }
  }
}

module.exports = Defragger
