OPENSSL ?= /work/ishikawa/tools/ssl
OPENSSL_SRC ?=/work/ishikawa/src/openssl
#
#CFLAGS = -DSGX_ENCLAVE_WITH_TPM2
#
INCL = -I../tpm2/ -I$(OPENSSL)/include -I$(OPENSSL_SRC)  -I$(OPENSSL_SRC)/include
LIBS =  -lssl -lcrypto
LIBNAME = libtlsra.so
SRCS_COMMON = libcert.c libtlsra.c libtpm2.c
HEAD_COMMON = libcert.h ptlsra.h
SRC_SGX     = libintel.c
HEAD_SGX    = sgxenv.h
OBJS  = $(SRCS_COMMON:.c=.o)
DEPS  = $(SRCS_COMMON:.c=.d) $(SRCS_SGX:.c=.d)

libtlsra.so: $(OBJS)
	ld -shared -o $@ $^
.c.o:
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(LIBNAME)

-include $(DEPS)
