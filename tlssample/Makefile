OPENSSL ?= /work/ishikawa/tools/ssl
OPENSSL_SRC ?=/work/ishikawa/src/openssl
INCL = -I$(OPENSSL)/include -I$(OPENSSL_SRC)  -I$(OPENSSL_SRC)/include
#LIBDIR = $(OPENSSL)/lib64
#LIBS =  -lssl -lcrypto -L$(LIBDIR)
LIBDIR = /usr/lib/x86_64-linux-gnu
LIBS =  -lssl -lcrypto

SRCS  = $(wildcard *.c)
OBJS  = $(SRCS:.c=.o)
DEPS  = $(SRCS:.c=.d)
PROGS = tlsclient tlsserver x509test

all: $(PROGS)
tlsclient: tlsclient.o libsock.o libmyssl.o
	cc -g -o $@ $^ $(LIBS)
tlsserver: tlsserver.o libsock.o libmyssl.o
	cc -g -o $@ $^ $(LIBS) -Wl,-rpath=$(LIBDIR)
x509test: x509test.o libsock.o libmyssl.o
	cc -g -o $@ $^ $(LIBS) -Wl,-rpath=$(LIBDIR)
#sslhttpclient: sslhttpclient.o
#	cc -g -o $@ $@.o -lssl -L$(LIBDIR)
clean:
	rm -f *.o *.d $(PROGS)
#
run-tlsra-server:
	./tlsserver -d -r -C
run-tlsra-client:
	./tlsclient -d

####################################################	
# Ore Ore CA
#	
oreore:
	@echo "***** Creating CA"
	mkdir -p CA
	openssl genrsa -out ./CA/my_ca.key 2048
	openssl req -x509 -new -nodes -key ./CA/my_ca.key -sha256 -days 3650 -out ./CA/my_ca.crt \
	-subj "/C=JP/ST=Tokyo/L=Chiyoda/O=ROIS/OU=CRADSEC/CN=cradsec-ca.rois.ac.jp"
	c_rehash ./CA/
#
#	server.key RSA
#	server.csr サーバ証明書要求ファイル
#	server.crt サーバ証明書 signed by ./CA/my_ca.crt
	@echo "***** Server Certificate"
	openssl genrsa -out server.key 2048
	openssl req -new -key server.key -out server.csr \
	-subj "/C=JP/ST=Tokyo/L=Chiyoda/O=ROIS/OU=CRADSEC/CN=cradsec-server.rois.ac.jp"
	openssl x509 -req -in server.csr -CA ./CA/my_ca.crt -CAkey ./CA/my_ca.key -CAcreateserial -out server.crt -days 365 -sha256


#
# self-signed certificate
#	public.key is a cert file
#	private.key is its private key
certgg:
	openssl req -new -x509 -nodes -out public.key -keyout private.key
.c.o:
	cc -g -O2 -MMD -Wall $(INCL) -c $< -o $@

run-tlsserver:
	./tlsserver -p 10101 -V -v
run-tlsclient:
	./tlsclient -d 127.0.0.1 -p 10101
run2-tlsserver:
	OPENSSL_CONF=./conf-mytest.cnf ./tlsserver -p 10101
run2-tlsclient:
	OPENSSL_CONF=./conf-mytest.cnf ./tlsclient -d 127.0.0.1 -p 10101
run-tlshttpclient:
	./sslhttpclient www.nii.ac.jp

-include $(DEPS)
