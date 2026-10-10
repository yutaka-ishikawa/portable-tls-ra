SGX_SDK ?= /opt/intel/sgxsdk
EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_EDGER_INCLUDE := -I$(SGX_SDK)/include
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign

SGX_LINUX-SGX	?= /home/ishikawa/work/linux-sgx/
SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/
SGX_SOCKET	:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgx_socket/
##SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/openssl_source/openssl-3.0.13/

#
SGX_LINUX-SGX	?= /home/ishikawa/work/linux-sgx/
SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/
SGX_SOCKET	:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgx_socket/
##SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/openssl_source/openssl-3.0.13/

##OPENSSL	    ?= /work/ishikawa/tools/ssl
##OPENSSL_SRC ?=/work/ishikawa/src/openssl
#
TSS2_INCPATH	?= ../external/
TSS2_LIB	:= -ltss2-mu -ltss2-esys
#
CBOR_INSTALL	?= ../external/
CBOR_INCPATH	:= $(CBOR_INSTALL)/include
CBOR_LIB	:= $(CBOR_INSTALL)/lib
#
JSON_INCPATH ?= /usr/include/json-c
JSON_LIB     := -ljson-c
#
MURMUR3_INCPATH ?= ../murmur3/
MURMUR3_LIB      = ../murmur3/murmur3.o
#
#
#TSS2_LIB  = -ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc
#
#CFLAGS = -DSGX_ENCLAVE_WITH_TPM2
#
INCL = -I. \
	-I$(TSS2_INCPATH) -I$(CBOR_INCPATH) -I$(JSON_INCPATH) -I$(MURMUR3_INCPATH) \
	-I../tpm2

LIBS =  -lssl -lcrypto 
HEAD_SGX    = sgxenv.h

#
TLSRA_INCL = $(INCL) -I../tpm2/

#
SGX_CFLAGS = -g -O2 -nostdinc -fvisibility=hidden -MMD -Wall -fPIC -DSGXENV -fPIC
SGX_INCL = -I. -I$(SGX_SDK)/include -I$(SGX_SSL)/include -I$(SGX_SDK)/include/tlibc \
	-I$(TSS2_INCPATH) -I$(CBOR_INCPATH) -I$(JSON_INCPATH) -I$(MURMUR3_INCPATH) \
	-I../tpm2

# TLSRA
TLSRA_LIBNAME = libtlsra.so
TLSRA_SRCS_COMMON = libcert.c libtlsra.c libtpm2.c
TLRSRA_HEAD_COMMON = libcert.h ptlsra.h
TLSRA_SRC_SGX     = libintel.c
TLSRA_OBJS  = $(TLSRA_SRCS_COMMON:.c=.o)
#
# PICA
PICA_SRCS_COMMON = libpica_common.c
PICA_OBJS_COMMON = $(PICA_SRCS_COMMON:.c=.o)
PICA_SRCS_CLNT = libpica_clnt.c libio.c libutil.c libmeasure.c
PICA_OBJS_CLNT_NORMAL = libpica_clnt-normal.o libio-normal.o libsock-normal.o \
	libutil-normal.o libmeasure.o libpica_common.o
PICA_OBJS_CLNT_SGX = libpica_clnt-sgx.o libio-sgx.o libsock-sgx.o \
	libutil-sgx.o

DEPS  = $(TLSRA_SRCS_COMMON:.c=.d) $(TLSRA_SRCS_SGX:.c=.d)  \
	$(PICA_SRCS_COMMON:.c=.d)

GETLIB_CMD ?= GETLIBS_CMD=\"$(PWD)/getlibs.sh\"

all: conftool libtlsra.so libpica_common.so libpica_clnt-normal.so libpica_clnt-sgx.a
conftool: conftool.c $(PICA_OBJS_CLNT_NORMAL) $(MURMUR3_LIB)
	$(CC) -g -O2 -o $@ $^ -D$(GETLIB_CMD) $(INCL) -L$(TSS2_INCPATH) -ltss2-mu -ltss2-rc -L$(CBOR_LIB) -lcbor -ljson-c -lcrypto
libtlsra.so: $(TLSRA_OBJS)
	ld -shared -o $@ $^
#libpica_clnt-sgx.so: $(PICA_OBJS_COMMON) $(PICA_OBJS_CLNT_SGX)
#	ld -shared -o $@ $^
libpica_clnt-sgx.a:  $(PICA_OBJS_COMMON) $(PICA_OBJS_CLNT_SGX)
	ar rcs $@ $^
libpica_common.so: $(PICA_OBJS_COMMON)
	ld -shared -o $@ $^
libpica_clnt-normal.so: $(PICA_OBJS_COMMON) $(PICA_OBJS_CLNT_NORMAL)
	ld -shared -o $@ $^
#
#
libpica_clnt-normal.o: libpica_clnt.c
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $< -o libpica_clnt-normal.o
libpica_clnt-sgx.o: libpica_clnt.c
	cc $(SGX_CFLAGS) $(SGX_INCL) -c $< -o libpica_clnt-sgx.o
libio-normal.o: libio.c libio.h pica_u.h
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $< -o libio-normal.o
libio-sgx.o: libio.c libio.h pica_t.h
	cc $(SGX_CFLAGS) $(SGX_INCL) -c $< -o libio-sgx.o
libsock-normal.o: libsock.c pica_u.h
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $< -o libsock-normal.o
libsock-sgx.o: libsock.c pica_t.h
	cc $(SGX_CFLAGS) $(SGX_INCL) -c $< -o libsock-sgx.o
libutil-normal.o: libutil.c pica_u.h
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $< -o libutil-normal.o
libutil-sgx.o: libutil.c pica_t.h
	cc $(SGX_CFLAGS) $(SGX_INCL) -c $< -o libutil-sgx.o
libmeasure.o: libmeasure.c
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $<
pica_u.o: pica_u.c pica_u.h
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(SGX_EDGER_INCLUDE) $(CFLAGS) -c $<
pica_t.o: pica_t.c pica_t.h
	cc $(SGX_CFLAGS) $(SGX_INCL) -c $<
#

# --- Edger8r codegen ---
pica_t.c pica_t.h: pica.edl
	$(EDGER8R) --trusted pica.edl \
	--search-path ./ \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--untrusted-dir ./
pica_u.c pica_u.h: pica.edl
	$(EDGER8R) --untrusted pica.edl \
	--search-path ./ \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--untrusted-dir ./
#
libcert.o libtlsra.o:
	cc -c -g -O2 -MMD -Wall -fPIC $(TLSRA_INCL) $(CFLAGS) -c $<
#
.c.o:
	cc -c -g -O2 -MMD -Wall -fPIC $(INCL) $(CFLAGS) -c $<

clean:
	rm -f $(TLSRA_OBJS) $(TLSRA_LIBNAME)
	rm -f $(PICA_OBJS_COMMON) $(PICA_OBJS_CLNT_NORMAL) $(PICA_OBJS_CLNT_SGX) *.so *.a

-include $(DEPS)
