const fs = require('fs')
const net = require('net')
const crypto = require('crypto')

const PRF = require('./iot/prf')
const {
  ClientHello,
  handleServerHello,
  handleServerCertificate,
  handleCertificateRequest,
  handleServerHelloDone,
  ClientCertificate,
  ClientKeyExchange,
  CertificateVerify,
  ClientFinished,
  deriveKeys,
  Cipher,
  Decipher,
  handleServerFinished
} = require('./iot/handshake')

/**
   enum {
       hello_request(0), client_hello(1), server_hello(2),
       certificate(11), server_key_exchange (12),
       certificate_request(13), server_hello_done(14),
       certificate_verify(15), client_key_exchange(16),
       finished(20)
       (255)
   } HandshakeType;
*/

let HandshakeMessages = []
let ClientSeqNum = Buffer.alloc(8)
let ServerSeqNum = Buffer.alloc(8)
let ClientRandom = Buffer.alloc(32)
let ServerRandom
let SessionId
let ServerPublicKey
let ServerCeritificates
let PreMasterSecret
let MasterSecret
let ClientWriteMacKey
let ServerWriteMacKey
let ClientWriteKey
let ServerWriteKey

let IncomingData = Buffer.alloc(0)

const TLSRecord = (type, packet) => Buffer.concat([
  Buffer.from([type,
    0x03, 0x03, // TLS 1.2
    (packet.length >> 8) & 0xff,
    packet.length & 0xff
  ]),
  packet
])

let Encryption = false

let client = new net.Socket()

client.on('connect', () => {
  crypto.randomFillSync(ClientRandom)
  let msg = ClientHello(ClientRandom)
  HandshakeMessages.push(msg)
  client.write(TLSRecord(0x16, msg))
})

client.on('data', data => {
  IncomingData = Buffer.concat([IncomingData, data])

  while (IncomingData.length >= 5) {
    let validTypes = [20, 21, 22, 23]
    let type = IncomingData[0]
    if (!validTypes.includes(type)) throw new Error('invalid tls record type')

    let length = IncomingData.readUInt16BE(3)
    if (IncomingData.length < length + 5) break

    let fragment = IncomingData.slice(5, 5 + length)
    IncomingData = IncomingData.slice(5 + length)

    switch (type) {
      case 20: { // change_cipher_spec
        console.log('server change cipher spec')
        break
      }

      case 21: { // alert
        console.log('server alert')
        console.log(fragment.length, fragment)
        break
      }

      case 22: { // handshake
        if (Encryption) {
          let msg = Decipher(fragment, ServerWriteMacKey, ServerWriteKey, ServerSeqNum)
          let digest = crypto.createHash('sha256')
            .update(Buffer.concat(HandshakeMessages)) 
            .digest()

          handleServerFinished(msg, MasterSecret, digest)
          console.log('connected')
          return
        }

        // hello_request not inclueded
        let bufferedTypes = [1, 2, 11, 12,13, 14, 15, 16, 20]
        let validTypes = [0, ...bufferedTypes]

        while (fragment.length) {
          if (fragment.length < 4) throw new Error('invalid fragment length')

          let type = fragment[0]
          let length = fragment[1] * 65536 + fragment[2] * 256 + fragment[3]
          let message = fragment.slice(0, 4 + length)
          fragment = fragment.slice(4 + length)
          
          if (bufferedTypes.includes(type)) HandshakeMessages.push(message) 

          switch (type) {
            case 2: { // server hello
              console.log('-- handle server hello')
              let r = handleServerHello(message.slice(4))
              ServerRandom = r.random
              SessionId = r.sessionId
              break
            }

            case 11: { // certificate
              let r = handleServerCertificate(message.slice(4))
              ServerPublicKey = r.publicKey  
              ServerCertificates = r.certs
              break
            }
  
            case 12: { // server key exchange
              break
            }

            case 13: { // certificate request
              console.log('-- handle certificate request')
              let r = handleCertificateRequest(message.slice(4))
              console.log(r)
              break
            }

            case 14: { // server hello done
              console.log('-- handle server hello done')
              handleServerHelloDone(message.slice(4))

              let msg, tbs, digest, key, r

              // client certificate
              let cert = Buffer.from(
                fs.readFileSync('deviceCert.crt')
                  .toString()
                  .split('\n')
                  .filter(x => !!x && !x.startsWith('--'))
                  .join(''), 'base64')

              msg = ClientCertificate([cert])
              HandshakeMessages.push(msg)
              client.write(TLSRecord(0x16, msg))

              // client key exchange
              PreMasterSecret = Buffer.alloc(48)
              crypto.randomFillSync(PreMasterSecret)
              PreMasterSecret[0] = 0x03
              PreMasterSecret[1] = 0x03

              msg = ClientKeyExchange(ServerPublicKey, PreMasterSecret)
              HandshakeMessages.push(msg)
              client.write(TLSRecord(0x16, msg))

              // client verify
              tbs = Buffer.concat(HandshakeMessages)
              key = fs.readFileSync('deviceCert.key')
              msg = CertificateVerify(key, tbs) 
              HandshakeMessages.push(msg)
              client.write(TLSRecord(0x16, msg))
              
              // change ciper spec 
              client.write(TLSRecord(0x14, Buffer.from([0x01])))

              // turn on Encryption
              Encryption = true

              r = deriveKeys(PreMasterSecret, ClientRandom, ServerRandom) 
              MasterSecret = r.masterSecret
              ClientWriteMacKey = r.clientWriteMacKey
              ServerWriteMacKey = r.serverWriteMacKey
              ClientWriteKey = r.clientWriteKey
              ServerWriteKey = r.serverWriteKey

              // client finished
              tbs = Buffer.concat(HandshakeMessages)
              digest = crypto.createHash('sha256').update(tbs).digest()
              msg = ClientFinished(MasterSecret, digest)
              HandshakeMessages.push(msg)

              let iv = Buffer.alloc(16)
              crypto.randomFillSync(iv)
              msg = Cipher(msg, ClientWriteMacKey, ClientWriteKey, iv)
              client.write(TLSRecord(0x16, msg)) 
              break
            }

            default: 
             
          }
        } 
        break
      }

      case 23: // application_data
        break

      default: // error
    }
  }

})

client.on('close', () => {
  console.log('connection closed')
})

client.connect(8883, 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn')
