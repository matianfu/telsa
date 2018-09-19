# iotls

iotls is a dangerously simple tls client implementation using node.js.

You may have two reasons to try this project:

1. you want to have some knowledge on tls internals.
2. you have a secure element, such as microchip atecc508a, on your linux hardware and just need a simple tlc client in node.js for mqtt.

This project is under development.

Goals: implement a minimal TLS 1.2 client solely for aws iot in node.js

1. only one cipher suite implemented (aes-128-cbc-sha)
2. only one certificate signature verification implemented (sha256-rsa)
3. based on a state machine pattern
4. compatible with node tls.socket interface (used with mqtt.js with minimal modification)
5. support hardware private key (atecc508a/608a)

# Constraints

During handshake stage:

1. server key exchange message is ignored.
2. server must require the client certificate.

