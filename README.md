# SSL-TLS-clientserver

SSL/TLS client server examples using openssl

## Build
```shell
$ mkdir build
$ cd build
$ cmake ..
$ make
$ cp -rf ../certs ./
```

## Test
### Server side
```shell
$ ./server
Certificate Verify Success
Client Hello World
```
### Client Side
```shell
$ ./client
Socket successfully created..
connected to the server..
Certificate Verify Success
SSL server send Client Hello World Appended by SSL serve
```
