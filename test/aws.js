const fs = require('fs')
const Telsa = require('../src/telsa')

const cert = fs.readFileSync('./certs/1f7394c39a-certificate.pem.crt')
const key = fs.readFileSync('./certs/1f7394c39a-private.pem.key')
const ca = fs.readFileSync('./certs/AmazonRootCA3.pem')

let conn = new Telsa({ 
  port: 8883,
  host: 'a1dn6p515gxf18.ats.iot.cn-north-1.amazonaws.com.cn',
  clientCertificates: [cert],
  clientPrivateKey: key,
  ca
})

conn.on('error', err => {
  console.log('error', err)
})

conn.on('close', () => {
  console.log('telsa closed (by server)')
})

