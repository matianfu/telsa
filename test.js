const fs = require('fs')
const TLS = require('.')

const MQTT_PINGREQ = Buffer.from([12 << 4, 0])
const MQTT_PINGRESP = Buffer.from([ 13 << 4, 0])

TLS.createConnection({
  port: 8883,
  host: 'a3dc7azfqxif0n.iot.cn-north-1.amazonaws.com.cn',
  // certs must be DER format
  clientCertificates: [
    Buffer.from(fs.readFileSync('deviceCert.crt')
      .toString()
      .split('\n')
      .filter(x => !!x && !x.startsWith('--'))
      .join(''), 'base64')
  ],
  // key is PEM format
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
