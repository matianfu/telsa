const fs = require('fs')
const TLS = require('.')

const MQTT_PINGREQ = Buffer.from([12 << 4, 0])
const MQTT_PINGRESP = Buffer.from([13 << 4, 0])

let ca = fs.readFileSync('ca.pem').toString().replace(/\r\n/g, '\n')
let clientCertificates = [
  Buffer.from(fs.readFileSync('deviceCert.crt')
    .toString()
    .split('\n')
    .filter(x => !!x && !x.startsWith('--'))
    .join(''), 'base64')
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

