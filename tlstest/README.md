
# building OpenSSL
```sh
cd $SRC
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure --prefix=/work/ishikawa/tools/ssl
make -j8

# building tltest
$ make
## creating self-signed CA for testing
#
$ make oreore


