const net = require('net')

let server = net.createServer(c => {
  console.log('server connection')
  setTimeout(() => {
    c.on('finish', () => console.log('server connection finish'))
    c.on('end', () => console.log('server connection end'))
    c.on('close', () => console.log('server connection close'))
    c.write('hello world')
    c.end()
    // c.destroy() 
    // server.close()
  }, 3000)
})

server.listen(8124, () => {
  console.log('server listening')
  let client = net.connect(8124, () => console.log('client connected'))
  client.on('finish', () => console.log('client finish'))
  client.on('readable', () => {
    console.log('readable')
    let data = client.read()
    console.log('data')
  })
  client.on('end', () => console.log('client end'))
  client.on('close', () => {
    console.log('client close')
    client.end()
  })
})


