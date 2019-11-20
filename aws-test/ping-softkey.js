const fs = require('fs')
const Telsa = require('../src/telsa')

const cert = fs.readFileSync('./certs/1f7394c39a-certificate.pem.crt')
const key = fs.readFileSync('./certs/1f7394c39a-private.pem.key')
const ca = fs.readFileSync('./certs/AmazonRootCA1.pem')
const port = 8883
const host = 'a1dn6p515gxf18.ats.iot.cn-north-1.amazonaws.com.cn'

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
