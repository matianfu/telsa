const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')
const net = require('net')

const PRF = require('./lib/prf')

const print = buffer => {
  while (buffer.length > 32) {
    console.log(buffer.slice(0, 32))
    buffer = buffer.slice(32)
  }

  if (buffer.length) console.log(buffer)
}


/**
    var mode = {
      // two 32-bit numbers, first is most significant                                      
      sequenceNumber: [0, 0],                                                               
      macKey: null,                                                                         
      macLength: 0,
      macFunction: null,                                                                    
      cipherState: null,
      cipherFunction: function(record) {return true;},                                      
      compressionState: null,
      compressFunction: function(record) {return true;},                                    
      updateSequenceNumber: function() {
        if(mode.sequenceNumber[1] === 0xFFFFFFFF) {                                         
          mode.sequenceNumber[1] = 0;                                                       
          ++mode.sequenceNumber[0];                                                         
        } else {
          ++mode.sequenceNumber[1];                                                         
        }                                                                                   
      }                                                                                     
    };
*/

/**
const state = {
  read: {
    sequenceNumber: Buffer.alloc(8),
    macKey: null,
    macLength: 0,
    macFunction: null,
    cipherState: null,
    cipherFunction: () => {},
    updateSequenceNumber: 
  },
  write: {
  },
}
*/

/**
var prf_TLS12 = function(secret, label, seed, length, hashType) {
   var rval = forge.util.createBuffer();

   var ai = forge.util.createBuffer();
   var shaBytes = forge.util.createBuffer();
   var hmac = forge.hmac.create();
   seed = label + seed;

   var shaItr = Math.ceil(length / 32);

   hmac.start(hashType, secret);
   ai.clear();
   ai.putBytes(seed);
   for(var i = 0; i < shaItr; ++i) {
     // HMAC_hash(secret, A(i-1))
     hmac.start(null, null);
     hmac.update(ai.getBytes());
     ai.putBuffer(hmac.digest());

     // HMAC_hash(secret, A(i) + seed)
     hmac.start(null, null);
     hmac.update(ai.bytes() + seed);
     shaBytes.putBuffer(hmac.digest());
   }
   rval.putBytes(shaBytes.getBytes(length));

   return rval;
};
*/

/**
const PRF = function (secret, label, seed, length, hashType) {
  seed = Buffer.concat([Buffer.from(label, 'binary'), seed])
  let shaItr = Math.ceil(length / 32)
  let ai = seed.slice(0)
  let shaBytes = Buffer.alloc(0)
  for (let i = 0; i < shaItr; ++i) {
    ai = crypto.createHmac(hashType, secret).update(ai).digest() 
    shaBytes = Buffer.concat([
      shaBytes,
      crypto.createHmac(hashType, secret)
        .update(Buffer.concat([ai, seed]))
        .digest()
    ])
  }
  return shaBytes.slice(length)
}
*/

/**
      handshake protocol
      enum {
          hello_request(0), client_hello(1), server_hello(2),
          certificate(11), server_key_exchange (12),
          certificate_request(13), server_hello_done(14),
          certificate_verify(15), client_key_exchange(16),
          finished(20), (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;    // handshake type
          uint24 length;             // bytes in message
          select (HandshakeType) {
              case hello_request:       HelloRequest;
              case client_hello:        ClientHello;
              case server_hello:        ServerHello;
              case certificate:         Certificate;
              case server_key_exchange: ServerKeyExchange;
              case certificate_request: CertificateRequest;
              case server_hello_done:   ServerHelloDone;
              case certificate_verify:  CertificateVerify;
              case client_key_exchange: ClientKeyExchange;
              case finished:            Finished;
          } body;
      } Handshake;

*/

/*

       struct {
           uint32 gmt_unix_time;
           opaque random_bytes[28];
       } Random;

      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;
*/

const typeMap = new Map()

typeMap.set(0, 'hello_request')
typeMap.set(1, 'client_hello')
typeMap.set(2, 'server_hello')
typeMap.set(11, 'certificate')
typeMap.set(12, 'server_key_exchange')
typeMap.set(13, 'certificate_request')
typeMap.set(14, 'server_hello_done')
typeMap.set(15, 'certificate_verify')
typeMap.set(16, 'client_key_exchange')
typeMap.set(20, 'finished')

const ClientHelloPayload = () => {
  // TLS 1.2
  let client_version = Buffer.from([0x03, 0x03])

  // time + random bytes
  clientHelloRandom = Buffer.alloc(32)
  crypto.randomFillSync(clientHelloRandom)
  clientHelloRandom.writeUInt32BE(Math.floor(new Date().getTime() / 1000))

  // session id length = 0
  let session_id = Buffer.from([0x00])

  /**

    CipherSuite TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
    CipherSuite TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
    CipherSuite TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
    CipherSuite TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
    CipherSuite TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
    CipherSuite TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
  * CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
    CipherSuite TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
    CipherSuite TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };

  * mandatory

  */
  let cipher_suites = Buffer.from([0x00, 0x02, 0x00, 0x2f])

  // no compression
  let compression_methods = Buffer.from([0x01, 0x00])

  return Buffer.concat([
    client_version,
    clientHelloRandom,
    session_id,
    cipher_suites,
    compression_methods
  ])
}

const HandshakeMessage = (type, message) =>
  Buffer.concat([
    Buffer.from([
      type,
      (message.length >> 16) & 0xff,
      (message.length >> 8) & 0xff,
      message.length & 0xff
    ]),
    message
  ])

const TLSRecord = (type, packet) =>
  Buffer.concat([
    Buffer.from([
      type,
      0x03, 0x03, // TLS 1.2
      (packet.length >> 8) & 0xff,
      packet.length & 0xff
    ]),
    packet
  ])

const ClientCertificateMessage = () => {
  // convert pem crt to der
  let certString = fs.readFileSync('deviceCert.crt')
    .toString()
    .split('\n')
    .filter(x => !!x && !x.startsWith('--'))
    .join('')

  let cert = Buffer.from(certString, 'base64')
  let certLen = Buffer.from([
    cert.length >> 16,
    cert.length >> 8,
    cert.length
  ])

  let certsLen = Buffer.from([
    (cert.length + 3) >> 16,
    (cert.length + 3) >> 8,
    (cert.length + 3)
  ])

  let payload = Buffer.concat([certsLen, certLen, cert])
  return HandshakeMessage(0x0b, payload)
}

/*
    struct {
        select (KeyExchangeAlgorithm) {
            case rsa:
                EncryptedPreMasterSecret;
            case dhe_dss:
            case dhe_rsa:
            case dh_dss:
            case dh_rsa:
            case dh_anon:
                ClientDiffieHellmanPublic;
        } exchange_keys;
    } ClientKeyExchange;

    encryptedPreMasterSecret is encrypted by server's public key
 */
const ClientKeyExchangeMessage = () => {
  preMasterSecret = Buffer.alloc(48)
  crypto.randomFillSync(preMasterSecret, 48)
  preMasterSecret[0] = 0x03
  preMasterSecret[1] = 0x03
  let encrypted = crypto.publicEncrypt(serverPubKey, preMasterSecret)
  let len16 = Buffer.from([encrypted.length >> 8, encrypted.length])
  let payload = Buffer.concat([len16, encrypted])
  return HandshakeMessage(0x10, payload)
}

const CertificateVerifyMessage = () => {
  let sigAlgorithm = Buffer.from([0x04, 0x01])
  let sigLength = Buffer.from([0x00, 0x00])
  let privateKey = fs.readFileSync('deviceCert.key')
  let sign = crypto.createSign('sha256')
  sign.update(tbsBuffers.pull())
  let sig = sign.sign(privateKey)
  sigLength.writeUInt16BE(sig.length)
  return HandshakeMessage(0x0f, Buffer.concat([sigAlgorithm, sigLength, sig]))
}

const ChangeCipherSpecMessage = () =>
  Buffer.from([
    0x14, // type
    0x03, 0x03, // version
    0x00, 0x01, // length
    0x01 // content
  ])

const EncryptedHandshakeMessage = () => {
  // generate master secret here
  let random = Buffer.concat([clientHelloRandom, serverHelloRandom])

  masterSecret = PRF(preMasterSecret, 'master secret', random, 48, 'sha256') 

  console.log('master secret', masterSecret.length, masterSecret)

  let keys = PRF(masterSecret, 'key expansion', random, 2 * (20 + 16), 'sha256')
  clientWriteMacKey = keys.slice(0, 20) 
  serverWriteMacKey = keys.slice(20, 40)
  clientWriteKey = keys.slice(40, 56)
  serverWriteKey = keys.slice(56, 72)

  // compute 12 byte hash
  let digest = crypto.createHash('sha256').update(tbsBuffers.pull()).digest()
  let hash = PRF(masterSecret, 'client finished', digest, 12, 'sha256')

  console.log('hash', hash.length, hash)

  let header = Buffer.from([
    0x16, // record type
    0x03, 0x03, // version
    (hash.length >> 8) & 0xff,
    hash.length & 0xff
  ])

  let record = Buffer.concat([Buffer.alloc(8), header, hash])
  let hmac = crypto.createHmac('sha1', clientWriteMacKey).update(record).digest() 

  console.log('hmac', hmac.length, hmac)

  let fragment = Buffer.concat([hash, hmac])

  let iv = Buffer.alloc(16)
  crypto.randomFillSync(iv)
  let cipher = crypto.createCipher('aes-128-cbc', clientWriteKey, iv)
  cipher.setAutoPadding(true)

  let encrypted = Buffer.concat([iv, cipher.update(fragment), cipher.final()])
  console.log('encrypted', encrypted.length)
  return encrypted

  // handshake finish message
//   let message = Buffer.concat([Buffer.from([0x14, 0x00, 0x00, 0x0c]), hash])

  // encrypt
  // let iv = Buffer.alloc(16)
  // let cipher = crypto.createCipheriv('aes-256-cbc', masterSecret, iv)
  // return Buffer.concat([cipher.update(message), cipher.final()])
  
}

let IncomingData = Buffer.alloc(0)
let clientHelloRandom
let serverHelloRandom
let sessionId
let serverPubKey
let preMasterSecret
let masterSecret

// 20 bytes
let clientWriteMacKey
let serverWriteMacKey
// 16 bytes
let clientWriteKey
let serverWriteKey

const messageLength = buf => buf[1] * 256 * 256 + buf[2] * 256 + buf[3]

class MessageBuffer {
  constructor () {
    this.msgs = []
  }

  push (msg, encrypted) {
    if (encrypted) {
      console.log('encrypted message', msg.length)
    } else if (msg[0] === 0x14) {
      console.log('change cipher spec', msg.length)
    } else {
      if (!(msg instanceof Buffer)) { throw new Error('error, not a buffer') }

      if (msg.length < 4) { throw new Error('invalid message length') }

      let len = msg[1] * 256 * 256 + msg[2] * 256 + msg[3]
      if (4 + len !== msg.length) { throw new Error('invalid message length') }

      console.log(`msg type: ${typeMap.get(msg[0])}, length: ${msg.length}`)
    }

    this.msgs.push(msg)
  }

  pull () {
    console.log('pulling tbs', this.msgs.length)
    let tbs = Buffer.concat(this.msgs)
    console.log('tbs', tbs.length)

    return tbs
  }
}

let tbsBuffers = new MessageBuffer()
let clientFinishedDone = false

let client = new net.Socket()

client.on('connect', () => {
  let msg = HandshakeMessage(0x01, ClientHelloPayload())
  tbsBuffers.push(msg)
  client.write(TLSRecord(0x16, msg))
})

client.on('data', data => {
  if (clientFinishedDone) {
    print(data)
    return
  }

  IncomingData = Buffer.concat([IncomingData, data])

  let msgBuf = Buffer.alloc(0)

  while (IncomingData.length >= 5) {
    let len = IncomingData.readUInt16BE(3)
    if (IncomingData.length < len + 5) break
    msgBuf = Buffer.concat([msgBuf, IncomingData.slice(5, 5 + len)])
    IncomingData = IncomingData.slice(5 + len)
  }

  while (msgBuf.length) {
    let type = msgBuf[0]
    let len = msgBuf.readUInt32BE(0) & 0x00ffffff
    let full = msgBuf.slice(0, 4 + len)

    let msg = msgBuf.slice(4, 4 + len)
    msgBuf = msgBuf.slice(4 + len)

    if (type === 0x02) { // server hello
      tbsBuffers.push(full)

      serverHelloRandom = msg.slice(2, 2 + 32)
      let sessionIdLength = msg.readUInt8(2 + 32)
      if (sessionIdLength) sessionId = msg.slice(2 + 32 + 1, 2 + 32 + 1 + sessionIdLength)
    } else if (type === 0x0b) { // server certificate
      tbsBuffers.push(full)

      /**
      0x0b <- handshake protocol, full starts here
        xx xx xx <- handshake message length
        xx xx xx <- Certificates Length, msg starts here
          xx xx xx <- certificate length starts here
      */

      let len = msg[0] * 256 * 256 + msg[1] * 256 + msg[2]

      msg = msg.slice(3)

      let certs = []
      while (msg.length) {
        let len = msg[0] * 256 * 256 + msg[1] * 256 + msg[2]
        certs.push(msg.slice(3, 3 + len))
        msg = msg.slice(3 + len)
      }

      certs.forEach((cert, i) => {
        // console.log(cert)
        fs.writeFileSync('server_cert_' + i + '.crt', cert)
        if (i === 0) {
          serverPubKey = child.execSync('openssl x509 -inform der -in server_cert_0.crt -noout -pubkey')
          // console.log('server pub key', serverPubKey.toString())
        }
      })
    } else if (type === 0x0c) { // server key exchange
      tbsBuffers.push(full)
      // console.log('server key exchange', len)
    } else if (type === 0x0d) {
      tbsBuffers.push(full)
      // console.log('certificate request', msg.length, msg)

      /**
      03 three certificate types
        01 rsa sign
        02 dss sign
        40 ecdsa sign
      00 1a signature hash algorithms: 26
        06 03 ecdsa_secp521r1_sha512
        06 01 rsa_pkcs1_sha512
        05 03 secp384r1_sha284
        05 01 rsa_pkcs1_sha384
        04 03 ecdsa_secp256r1_sha256
        04 01 rsa_pkcs1_sha256
        04 02 SHA256 DSA
        03 03 SHA224 ECDSA
        03 01 SHA224 RSA
        03 02 SHA224 DSA
        02 03 ecdsa_sha1
        02 01 rsa_pkcs1_sha1
        02 02 SHA1 DSA
      00 00 Distinguished Names Length: 0
      */
    } else if (type === 0x0e) {
      tbsBuffers.push(full)
      // console.log('server hello done')

      let payload, msg

      // 1. certificate
      msg = ClientCertificateMessage()
      tbsBuffers.push(msg)
      client.write(TLSRecord(0x16, msg))

      // 2. client key exchange,
      msg = ClientKeyExchangeMessage()
      tbsBuffers.push(msg)
      client.write(TLSRecord(0x16, msg))

      // 3. certificate verify,
      msg = CertificateVerifyMessage()
      tbsBuffers.push(msg)
      client.write(TLSRecord(0x16, msg))

      // 4. change cipher spec,
      msg = ChangeCipherSpecMessage()
      // tbsBuffers.push(msg)
      // client.write(TLSRecord(0x16, msg))
      client.write(msg)

      // 5. encrypted handshake message
      msg = EncryptedHandshakeMessage()
      // TODO tbsBuffers.push(msg, true)
      client.write(TLSRecord(0x16, msg))

      clientFinishedDone = true
    } else {
      console.log('unknown type', msg[0], msg)
    }
  }
})

client.on('close', () => {
  console.log('connection closed')
})

client.connect(8883, 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn')
