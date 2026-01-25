OBJS=	libcert.o libintel.o
LIBS=	-lcrypto -lcbor
all: $(OBJS)
	gcc -g libcert.o libintel.o $(LIBS)
.c.o:
	gcc -g -c $<

show-cert:
	openssl x509 -in mycert.pem -text -noout
verify:
	openssl verify -CAfile mycert.pem mycert.pem
