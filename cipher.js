/**

tls.CipherSuites['TLS_RSA_WITH_AES_128_CBC_SHA'] = {
  id: [0x00,0x2f],
  name: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  initSecurityParameters: function(sp) {
    sp.bulk_cipher_algorithm = tls.BulkCipherAlgorithm.aes;
    sp.cipher_type = tls.CipherType.block;
    sp.enc_key_length = 16;
    sp.block_length = 16;
    sp.fixed_iv_length = 16;
    sp.record_iv_length = 16;
    sp.mac_algorithm = tls.MACAlgorithm.hmac_sha1;
    sp.mac_length = 20;
    sp.mac_key_length = 20;
  },
  initConnectionState: initConnectionState
};

**/

const SecurityParameters = {
  bulkCipherAlgorithm = 'aec',
  cipherType: 'block',
  encKeyLength: 16,
  blockLength: 16,
  fixedIvLength: 16,
  recordIvLength: 16,
  macAlgorithm: 'hmac_sha1',
  macLength: 20,
  macKeyLength: 20
}

