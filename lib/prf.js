const crypto = require('crypto')

module.exports = (secret, label, seed, length, hashType) => {
  // !important, use binary encoding
  seed = Buffer.concat([Buffer.from(label, 'binary'), seed])

  let A = Buffer.from(seed)
  let P_HASH = Buffer.alloc(0)

  for (let i = 0; i < Math.ceil(length / 32); ++i) {
    A = crypto.createHmac(hashType, secret).update(A).digest()

    let hmac = crypto
      .createHmac(hashType, secret)
      .update(Buffer.concat([A, seed]))
      .digest()

    P_HASH = Buffer.concat([P_HASH, hmac])
  }

  return P_HASH.slice(0, length)
}

