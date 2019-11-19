const fs = require('fs')
const Telsa = require('../src/telsa')
const TLS = require('tls')

const cert = fs.readFileSync('./certs/1f7394c39a-certificate.pem.crt')
const key = fs.readFileSync('./certs/1f7394c39a-private.pem.key')
const ca = fs.readFileSync('./certs/AmazonRootCA1.pem')

const MQTT_PINGREQ = Buffer.from([12 << 4, 0]) 
const MQTT_PINGRESP = Buffer.from([13 << 4, 0]) 

console.log('ping_req', MQTT_PINGREQ)
console.log('ping_resp', MQTT_PINGRESP)

if (true) {
  const telsa = new Telsa({ 
    port: 8883,
    host: 'a1dn6p515gxf18.ats.iot.cn-north-1.amazonaws.com.cn',
    key,
    cert, 
    ca
  })

  telsa.on('error', err => console.log('telsa error', err))
  telsa.on('data', data => console.log('telsa data', data))
  telsa.on('finish', () => console.log('telsa finish'))
  telsa.on('end', () => console.log('telsa end'))
  telsa.on('close', () => console.log('telsa close'))
  telsa.write(MQTT_PINGREQ)
  telsa.end()
  // setTimeout(() => telsa.destroy(new Error('hello')), 1000)

} else {
  const tls = TLS.connect({
    port: 8883,
    host: 'a1dn6p515gxf18.ats.iot.cn-north-1.amazonaws.com.cn',
    key,
    cert,
    ca
  })

  tls.on('error', err => console.log('tls error', err))
  tls.on('data', data => console.log('tls data', data))
  tls.on('finish', () => console.log('tls finish'))
  tls.on('end', () => console.log('tls end'))
  tls.on('close', () => console.log('tls close'))
  tls.write(MQTT_PINGREQ)
  
  setTimeout(() => tls.destroy(new Error('hello')), 1000)
}



