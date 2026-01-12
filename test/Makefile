OPENSSL ?= /work/ishikawa/tools/ssl
OPENSSL_LIBDIR = /work/ishikawa/tools/ssl/lib64
TLSRA_LIBDIR = ../src/
TLSRA_INCDIR = ../src/
INCL=	-I$(TLSRA_INCDIR)
LIBS =  -L$(OPENSSL_LIBDIR) -lssl -lcrypto -L$(TLSRA_LIBDIR) -ltlsra
OBJ = libtest.o

PROGS = tlsra_server tlsra_client

all: $(PROGS)
tlsra_server: tlsra_server.o $(OBJ)
	cc -g -o $@ $^ $(LIBS) -Wl,-rpath=$(OPENSSL_LIBDIR):$(TLSRA_LIBDIR)
tlsra_client: tlsra_client.o $(OBJ)
	cc -g -o $@ $^ $(LIBS) -Wl,-rpath=$(OPENSSL_LIBDIR):$(TLSRA_LIBDIR)
clean:
	rm -f $(PROGS) $(OBJ)

#
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

#
#
#
run-tlsra_server:
	./tlsra_server -p 10101 -V -v -r
run-tlsra_client:
	./tlsra_client -d 127.0.0.1 -p 10101

