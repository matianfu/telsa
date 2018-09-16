const fs = require('fs')
const child = require('child_process')
const crypto = require('crypto')
const net = require('net')

const print = buffer => {
  while (buffer.length > 32) {
    console.log(buffer.slice(0, 32))
    buffer = buffer.slice(32)
  }

  if (buffer.length) console.log(buffer)
}

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

const ClientHelloExtension = (type, body) => {
  return Buffer.concat([
    
  ])
}

const ClientHelloExtensions = () => {
   
}

const ClientHelloPayload = () => {
  // TLS 1.2
  let client_version = Buffer.from([0x03, 0x03]) 

  // time + random bytes
  let random = Buffer.alloc(32)
  random.writeUInt32BE(Math.floor(new Date().getTime() / 1000))
  crypto.randomFillSync(random, 4)

  // session id length = 0
  let session_id = Buffer.from([0x00])

  // TLS_RSA_WITH_AES_256_CBC_SHA
  let cipher_suites = Buffer.from([0x00, 0x02, 0x00, 0x35])

  // no compression
  let compression_methods = Buffer.from([0x01, 0x00]) 

  return Buffer.concat([
    client_version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
  ]) 
}

const HandshakeMessage = (type, message) => 
  Buffer.concat([
    Buffer.from([
      type, 
      (message.length >> 16) & 0xff,
      (message.length >> 8) & 0xff,
      message.length & 0xff,
    ]),
    message
  ])

const TLSRecord = (type, packet) => 
  Buffer.concat([
    Buffer.from([
      type,
      0x03, 0x03,             // TLS 1.2
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

  console.log('certString', certString)

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
  let sigLength = Buffer.from([0x00, 0x00]) // 256
  let digest = crypto.createHash('sha256').update(Buffer.concat(tbsBuffers)).digest()
  let sig = crypto.privateEncrypt(fs.readFileSync('deviceCert.key'), digest)
  sigLength.writeUInt16BE(sig.length)
  return HandshakeMessage(0x0f, Buffer.concat([sigAlgorithm, sigLength, sig]))
}

const ChangeCipherSpecMessage = () => 
  HandshakeMessage(0x14, Buffer.from([0x01]))

const EncryptedHandshakeMessage = () => Buffer.alloc(64)

let IncomingData = Buffer.alloc(0)
let serverRandom
let sessionId
let preMasterSecret
let serverPubKey
let tbsBuffers = []



let client = new net.Socket()

client.on('connect', () => {
  let handshakeClientHello = HandshakeMessage(0x01, ClientHelloPayload())
  tbsBuffers.push(handshakeClientHello)
  let message = TLSRecord(0x16, handshakeClientHello)
  print(message)
  client.write(message)
  // client.flush()
})

client.on('data', data => {
  print(data)

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

      serverRandom = msg.slice(2, 2 + 32)
      let sessionIdLength = msg.readUInt8(2 + 32)
      if (sessionIdLength) sessionId = msg.slice(2 + 32 + 1, 2 + 32 + 1 + sessionIdLength)

      console.log('server hello, server random', serverRandom)
      console.log('session id', sessionIdLength, sessionId)

      console.log('---------------------, msg.length', msg.length)
      print(msg)
      console.log('---------------------')


    } else if (type === 0x0b) { // server certificate
      tbsBuffers.push(full)

      console.log('----- full certs -----')
      print(full)
      console.log('----- divider -----')
      print(msg)
      console.log('----- msg -----')
      /**
      0x0b <- handshake protocol, full starts here
        xx xx xx <- handshake message length
        xx xx xx <- Certificates Length, msg starts here
          xx xx xx <- certificate length starts here
      */

      let len = msg[0] * 256 * 256 + msg[1] * 256 + msg[2]
      console.log(msg[0])
      console.log(msg[1])
      console.log(msg[2])
      console.log('certificatesLength', len)

      msg = msg.slice(3)

      let certs = []
      while (msg.length) {
        let len = msg[0] * 256 * 256 + msg[1] * 256 + msg[2]
        certs.push(msg.slice(3, 3 + len))
        msg = msg.slice(3 + len)
      }

      certs.forEach((cert, i) => {
        console.log(cert)
        fs.writeFileSync('server_cert_' + i + '.crt', cert)
        if (i === 0) {
          serverPubKey = child.execSync('openssl x509 -inform der -in server_cert_0.crt -noout -pubkey')
          console.log('server pub key', serverPubKey.toString())
        }
      })
    } else if (type === 0x0c) { // server key exchange
      tbsBuffers.push(full)
      console.log('server key exchange', len)
    } else if (type === 0x0d) {
      tbsBuffers.push(full)
      console.log('certificate request', msg.length, msg)

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
      console.log('server hello done')

      let payload, msg

      // send 
      // 1. certificate
      // 2. client key exchange, 
      // 3. certificate verify, 
      // 4. change cipher spec, 
      // 5. encrypted handshake message

      msg = ClientCertificateMessage()
      tbsBuffers.push(msg) 
      client.write(TLSRecord(0x16, msg))

      msg = ClientKeyExchangeMessage()
      tbsBuffers.push(msg) 
      client.write(TLSRecord(0x16, msg))

      msg = CertificateVerifyMessage() 
      client.write(TLSRecord(0x16, msg))
/*
      msg = ChangeCipherSpecMessage()
      client.write(TLSRecord(0x16, msg))

      msg = EncryptedHandshakeMessage()
      client.write(TLSRecord(0x16, msg))
*/

    } else {
      console.log('unknown type', msg[0], msg)
    }
  }
})

client.on('close', () => {
  console.log('connection closed')
})

client.connect(8883, 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn')



