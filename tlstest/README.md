
# Building OpenSSL
```sh
cd $SRC
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure --prefix=/work/ishikawa/tools/ssl
make -j8
```

# Building tltest
```sh
$ make
```

## Creating self-signed CA for testing
```sh
$ make oreore
```
- The following files have been created under the ./CA directory
  - my_ca.key
  - my_ca.crt
  - my_ca.srl
  - files created by the c_rehash command
