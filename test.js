const fs = require('fs')
const TLS = require('.')

const MQTT_PINGREQ = Buffer.from([12 << 4, 0])
const MQTT_PINGRESP = Buffer.from([13 << 4, 0])

TLS.createConnection({
  port: 8883,
  host: 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn',
  // PEM format
  ca: fs.readFileSync('ca.pem').toString().replace(/\r\n/g, '\n'),
  // convert to DER format
  clientCertificates: [
    Buffer.from(fs.readFileSync('deviceCert.crt')
      .toString()
      .split('\n')
      .filter(x => !!x && !x.startsWith('--'))
      .join(''), 'base64')
  ],
  // PEM format
  clientPrivateKey: fs.readFileSync('deviceCert.key')

}, (err, tls) => {
  console.log('tls connected')
  tls.once('data', data => {
    if (data.equals(MQTT_PINGRESP)) {
      console.log('MQTT_PINGESP received')
    } else {
      console.log('server replied: ', data)
    }
  })

  tls.write(MQTT_PINGREQ) 
  console.log('MQTT_PINGREQ sent to server')
})

/**
let ca = fs.readFileSync('ca.pem').toString().replace(/\r\n/g, '\n')
let clientCerificates = [
]
let clientPrivateKey = fs.readFileSync('deviceCert.key')

let tls = new TLS({ ca, clientCertificates, clientPrivateKey })
tls.on('error', err => console.log(err))
tls.connect(8883,'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn', () => {
  tls.once('data', data => {
    if (data.equals(MQTT_PINGRESP)) {
      console.log('MQTT_PINGRESP received')
    } else {
      console.log('unexpected server response: ', data)
    }
  }) 
  tls.write(MQTT_PINGREQ)
  console.log('MQTT_PINGREQ sent to server')
})
*/

