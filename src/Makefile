OPENSSL ?= /work/ishikawa/tools/ssl
OPENSSL_SRC ?=/work/ishikawa/src/openssl
INCL = -I$(OPENSSL)/include -I$(OPENSSL_SRC)  -I$(OPENSSL_SRC)/include
LIBS =  -lssl -lcrypto
LIBNAME = libtlsra.so
SRCS  = $(wildcard *.c)
OBJS  = $(SRCS:.c=.o)
DEPS  = $(SRCS:.c=.d)

libtlsra.so: $(OBJS)
	ld -shared -o $@ $^
.c.o:
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) -c $<

clean:
	rm -f $(OBJS) $(LIBNAME)

-include $(DEPS)
