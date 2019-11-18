const fs = require('fs')
const pki = require('node-forge').pki

const ca = pki.certificateFromPem(fs.readFileSync('./certs/AmazonRootCA1.pem').toString())

const caStore = pki.createCaStore([ ca ])

const cert0 = pki.certificateFromPem(fs.readFileSync('./cert0.pem').toString())
const cert1 = pki.certificateFromPem(fs.readFileSync('./cert1.pem').toString())
const cert2 = pki.certificateFromPem(fs.readFileSync('./cert2.pem').toString())
const cert3 = pki.certificateFromPem(fs.readFileSync('./cert3.pem').toString())


console.log('cert0')
console.log(' subject', cert0.subject.attributes)
console.log(' issuer', cert0.issuer.attributes)

console.log('cert1 is issuer of cert 0', cert0.isIssuer(cert1))
console.log('cert2 is issuer of cert 0', cert0.isIssuer(cert2))
console.log('cert3 is issuer of cert 0', cert0.isIssuer(cert3))

console.log('cert2 is issuer of cert 1', cert1.isIssuer(cert2))
console.log('cert3 is issuer of cert 1', cert1.isIssuer(cert3))

console.log('cert3 is issuer of cert 2', cert2.isIssuer(cert3))

console.log('ca is issuer of cert 0', cert0.isIssuer(ca))
console.log('ca is issuer of cert 1', cert1.isIssuer(ca))
console.log('ca is issuer of cert 2', cert2.isIssuer(ca))
console.log('ca is issuer of cert 3', cert3.isIssuer(ca))


console.log('cert1')
console.log(' subject', cert1.subject.attributes)
console.log(' issuer', cert1.issuer.attributes)

console.log('ca')
console.log(' subject', ca.subject.attributes)
console.log(' issuer', ca.issuer.attributes)

/**
console.log(cert1)
console.log(cert2)
console.log(cert3)
*/

const chain = [cert0, cert1, cert2, cert3]
const chain2 = [cert3, cert2, cert1, cert0]

try {
  const verified = pki.verifyCertificateChain(caStore, [ cert0, cert1 ])
  console.log(verified)

  console.log(pki.publicKeyToPem(cert0.publicKey))

} catch (e) {
  console.log(e)
}
