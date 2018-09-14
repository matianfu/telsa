# aws-iot-tls-client

TLS 1.2 for aws iot client

This project is under development.

Goals: implement a minimal TLS 1.2 client solely for aws iot things.

1. only one cipher suite implemented (aes128-sha256)
2. only one certificate signature verification implemented (sha256-rsa)
3. based on a state machine pattern
4. compatible with node tls interface (used with mqtt.js with minimal modification)
5. support hardware private key (atecc508a/608a)

