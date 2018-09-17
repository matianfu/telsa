const path = require('path')
const chai = require('chai')
const expect = chai.expect

const prf = require('lib/prf')

describe(path.basename(__filename), () => {
  it('should pass test 1', done => {
    const random = Buffer.from('e4f86f1b305ed42291e3c3eaf326bca62c5fddc95facb2b22561a501b1d5faee3c0665fb76bb194c1be0c45875d62dd319acf148c589d7cfb7e31912dac84901', 'hex')
    const preMaster = Buffer.from('0303b866f3f9ce3fd9162f76a8d7eb1dcaa992bd14a8fd7ad2f8acb3eb19c920419873203d359baf8eb133eaf4aac953', 'hex')
    const masterHex = '89680a109ed2f084eaec2083ab4a3d66be7e5d26c11a86e878ca6ed6e56581f40926ca2ae3e1342f16db27d245ec281c'

    let master = prf(preMaster, 'master secret', random, 48, 'sha256')
    expect(masterHex).to.equal(master.toString('hex'))
    done()
  })

  it('should pass test 2', done => {
    const random = Buffer.from('e50188c4dec5ea205660e31be1668994c5c3fc508e736bd7be1366697aee0840b02800db3bc3fd8bfa125d18740940b2c1764343d64a6999458fffff91e720b5', 'hex')
    const preMaster = Buffer.from('03035ee4feb09e3625f86527cd7e042d65c01aaa9e72e2da6fe514019127c487a946f11e7c0b74e40a3eca83a7a27179', 'hex')
    const masterHex = '497d81f63c29545e3b65e71b9c3967d8f07d7df01c9be0738eacc605b4440f26c1ed46ccd1aa685971f52569db8e3dda'

    let master = prf(preMaster, 'master secret', random, 48, 'sha256')
    expect(masterHex).to.equal(master.toString('hex'))
    done()
  })
})
