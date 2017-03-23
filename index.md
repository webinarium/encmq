## About EncMQ ##

This library provides simple and easy-to-use API for messages interchange between your C++ applications over network. The project was inspired by [ZeroMQ](http://www.zeromq.org/) library and is an upper-level tier on top of it. Main goal of the library is to append ZeroMQ with seamless serialization and encryption.

## Library Building ##

EncMQ pretends to be a cross-platform library, so you probably can use any compiler on any system. The proven cases are GCC for Linux and Visual Studio 2008 or later for Windows - both are fine and can be used to build the project. More details about how to build the project can be found at the [project's wiki](https://github.com/arodygin/encmq/wiki/Library-Building).

## Serialization ##

The library uses [Protocol Buffers](https://developers.google.com/protocol-buffers/) for serialization. There are a lot of examples in the [project's wiki](https://github.com/arodygin/encmq/wiki/Serialization) regarding how to use it.

## Encryption ##

A traffic between server and client can be encrypted using AES-128 in OFB mode (EncMQ uses [OpenSSL](http://www.openssl.org/) library). To make the traffic secured a client will generate random symmetric key when connects to a server. This key is automatically provided in each message being sent to a server to make the server able to decrypt the message. Of course, the key can be intercepted, which makes no sense to the encryption. To avoid it, this key is also encrypted using asymmetric RSA, where public key is available to any client while private key belongs to a server.

To avoid injections into transfering messages, each message (from both client and server) is signed with message authentication code using HMAC via SHA-160. If receiver found that MAC of just arrived message is wrong, the message is ignored and corresponding exception is raised.

## Request-reply connections ##

Request-reply schema is a classic client/server connection. A client connects to a server's IP and sends a single message _(request)_. A server is permanently listening for requests and processes each received. Server can also respond on the request, sending another message back _(reply)_. Each reply is sent directly to the client, originated the request. If your protocol between server and client supposes that some message must be replied, then client has to wait for this reply before sending another request. More details about this schema can be found at the [project's wiki](https://github.com/arodygin/encmq/wiki/Request-Reply-Schema).

## Publish-subscribe connections ##

In the request-reply schema above a client plays an active role in interaction and initiates an exchange, while a server is passive and replies only when being requested. The publish-subscribe schema is something reverse, where server is an active player. Moreover, a server _(publisher)_ can only send messages, and a client _(subscriber)_ - can only receive. The server sends messages on some basis w/out any bothering from outside. Any client, who wants to receive these messages, has to explicitly subscribe using server's IP. The schema is described in details at the [project's wiki](https://github.com/arodygin/encmq/wiki/Publish-Subscribe-Schema).
