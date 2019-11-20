Telsa is a minimal and pure JavaScript TLS 1.2 implementation for aws iot devices authenticated with hardware private key. 

Theoretically this should be done via openssl engine. In practice, however, there are lots of troubles in  maintaining the compatibility among linux drivers, Microchip CryptoAuthLib, openssl engine, and Node, which statically-links libopenssl. 

Telsa has many limitations:
1. it supports only TLS v1.2
2. it supports only `TLS_RSA_WITH_AES_128_CBC_SHA` cipher suite, which is mandatory in TLS v1.2
3. it has no support for compression
4. it supports only RSA in public key signature for server certficate, due to limitation of forge
5. the server MUST issue a CertificateRequest during handshake, otherwise, Telsa will throw an error

In constructing a Telsa connection, a `key` must be provided as an option property. It may be a PEM format private key, or an asynchronous function that cound sign a chunk of data. Telsa will use the signature in CertifiateVerify hanshake message.

For some iot devices, system local time may be incorrect temporarily. `validityCheckDate` is provided as an option to skip validating the certificate validity period.

Telsa extends node `stream.Duplex`. All node stream events are available. `Destroy` method is implemented. Flow control is implemented. The performance should be more than enough for mqtt application.

Telsa is not a drop-in replacement for node TLS. It is simpler. A `connect` event is emitted after a TLS handshaking. There is no `secureConnect` event. Data should be written or piped into Telsa before a `connect` event.



# Example

```js
const fs = require('fs')
const Telsa = require('../src/telsa')

# change certs and keys to your own
const cert = fs.readFileSync('./certs/1f7394c39a-certificate.pem.crt')
const key = fs.readFileSync('./certs/1f7394c39a-private.pem.key')
const ca = fs.readFileSync('./certs/AmazonRootCA1.pem')
const port = 8883

# change host to your own
const host = 'a1dn6p515gxf18.ats.iot.cn-north-1.amazonaws.com.cn'

# mqtt ping message
const MQTT_PINGREQ = Buffer.from([12 << 4, 0]) 
const MQTT_PINGRESP = Buffer.from([13 << 4, 0]) 

const tls = new Telsa({ port, host, key, cert, ca })

tls.on('error', err => console.log('error', err))
tls.on('data', data => console.log('data', data))
tls.on('finish', () => console.log('finish'))
tls.on('end', () => console.log('end'))
tls.on('close', () => console.log('close'))

tls.write(MQTT_PINGREQ)

setTimeout(() => tls.end(), 2000)
```



Running the code should get the following output:

```
$ node aws-test.js
data <Buffer d0 00>
finish
end
close
```



Noticing that the last line in code has a `setTimeout`. Telsa ends the connection **SYNCHRONOUSLY**. Without this delay, your should not see the received data, which is a MQTT_PINGRESP. If this line is commented out, after a few seconds, aws cloud will end the connection.



Unlike a tcp connection, there is no half-open connection in TLS. 

1. A closure may be initiated by either party by sending a close_notify alert (or a fatal alert).
2. The responder MUST reply a close_notify and close down both read side and write side of the connection IMMEDIATELY.
3. The initiator may wait for the response, as the node TLS does. But TLS allows the initiator to close down both sides of the connection immediately without waiting for the reply. Telsa adopts this way.



# new Telsa(opts)

Constructs a Telsa object.

- `opts` `<Object>`
  - `port` `<number>` server port
  - `host` `<string>` server domain name, must be a Fully-Qualified Domain Name (FQDN)
  - `ca` `<string>` root CA certificate in PEM format
  - `cert` `<string>` client certificate in PEM format
  - `key` `<string>` or `<function>`
    - if `key` is a `<string>`, it is the client public key in PEM format
    - if `key` is a `<function>`, it is a Signing function, see below.
  - `[validityCheckDate]` `<Date>` or `null`, the server certificate chain will be verified against the given date, rather than the current system time, if provided. If the option is `null`, the validity period will NOT be checked during verification.
  - `[socket]` `<Object>`, this option is used for testing only, for mocking a socket.



## Signing Function `(data, callback) => {}`

A signing function accepts a chunk of data and returns the signature in callback function.

* data `<Buffer>` data to be signed
* callback `<function>`, in the form of `(err, sig) => {}`, where:
  * err `<Error>` error
  * sig `<Buffer>` signature

