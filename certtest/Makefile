LIBS=	-lcrypto -lcbor
all:
	gcc -g libcert.c $(LIBS)

show-cert:
	openssl x509 -in mycert.pem -text -noout
verify:
	openssl verify -CAfile mycert.pem mycert.pem
