# SSL-TLS-clientserver

SSL/TLS client server examples using openssl

## Build
```shell
$ make
$ adb shell mkdir -p /usrdata/test/certs/
$ adb push output/gd_se_test /usrdata/test/
$ adb push certs/* /usrdata/test/certs/
```

## Test
```shell
$ adb shell
$ cd /usrdata/test/
$ ./gd_se_test
```
