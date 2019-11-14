/**
content type for TLS record layer
@readonly
@enum {number}
*/
const ContentType = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
}

module.exports = {
  ContentType
}
