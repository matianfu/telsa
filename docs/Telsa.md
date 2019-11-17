Telsa





# Interface and External States

`telsa` implements `stream.Duplex` class. All methods and events for `stream.Writable` and `stream.Readable` are available to users, except for the `destroy` method, which is not implemented yet.



`telsa` does not have a separate `connect` method. All connection related parameters must be provided during construction. 



`telsa` will emit a `connect` event after 



From the user perspective, `telsa` has three states:

1. (tls) connecting
2. established
3. disconnected (with a reason code)



`telsa` starts from `connecting` state after construction. It will emit a `connect` event if the secure connection is established successfully, or an `error` event if it fails.

 





Internally, telsa has the following states:

1. (socket) connecting
2. handshaking
3. established
4. disconnected (with a reason code)



From the user perspective, both (socket) connecting and handshaking are (tls) connecting state. 

If telsa fails to establish a secure connection, it transits to disconnected with a reason code `connectFailed`.

If `_final` is invoked during (tls) connecting state, which means `end` is invoked on duplex stream without any `write`, telsa goes into `disconnected` state with a reason code `connectFinalized`. This is essentially a user `cancel` or `destroy`.









Error Handling

1. a socket close (without error or alert), need definition ERR_TLS_SOCKET_CLOSE

2. a socket error (all socket errors end the connection. `close` event follows `error` event.

3. a fatal alert from server, need definition ERR_TLS_FATAL_ALERT (with description)

4. an error occurs handling socket data (including asynchronous function) ERR_TLS_FATAL_ERROR (with description)

5. a close_notify warning alert from server ERR_TLS_CLOSE_NOTIFY

In case 1, 2, and 3 there is no chance or no need to write anything to socket.

In case 4, an fatal alert should be sent before ending the socket.

In case 5, an reply of close_notify should be sent.



1, 2, 3, 4 are considered to be error state, but 5 may be OK if there is no pending or draining write.

In all cases, if there are pending or draining write, the write callback should be invoked with the original error in case 2 and 4. In other cases, the following error:


```
This socket has been ended by the other party
EPIPE
```



If there is no pending or draining write, in case 1, 2, 3, and 4, the error is emitted, followed by a close immediately. In case 5, the read path is ended with a push(null), followed by a close.



----



_final













