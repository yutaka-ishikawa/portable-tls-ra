#
# PICA PoC
#	Host/untrusted_sgx_socket.c comes from Intel SDK
#
TSS2_INSTALL	?= ../external/
TSS2_INCPATH	:= $(TSS2_INSTALL)/include/tss2
TSS2_LIB	:= $(TSS2_INSTALL)/lib
JSON_SGXPATH	?= ../json-c-sgx/json-c/build-sgx
JSON_SGXLIB	:= -ljson-c-sgx
CBOR_INSTALL	?= ../external/
CBOR_INCPATH	:= $(CBOR_INSTALL)/include
CBOR_LIB	:= $(CBOR_INSTALL)/lib

SGX_SDK		?= /opt/intel/sgxsdk
EDGER8R		:= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_EDGER_INCLUDE := -I$(SGX_SDK)/include
SGX_SIGN	:= $(SGX_SDK)/bin/x64/sgx_sign

SGX_LINUX-SGX	?= /home/ishikawa/work/linux-sgx/
SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/
SGX_SOCKET	:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgx_socket/

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_SSLLIB_PATH := $(SGX_SSL)/lib64
SGX_INCLUDE	:= -I$(SGX_SDK)/include -I$(SGX_SOCKET)/include -I$(SGX_SSL)/include -I$(SGX_SDK)/include/tlibc -I$(TSS2_INCPATH)
SGX_CFLAGS	:= -DSGXENV -Wall -O2 -g $(SGX_HOSTINCLUDE)

HOST_CFLAGS	:= -Wall -O2 -g $(SGX_HOSTINCLUDE)
HOST_INCLUDE	:= -IHost/ -I$(SGX_SDK)/include
#
EDL		:= Enclave/pica_poc.edl
#
#
JSON_SGX_PATH	?= ../json-c-sgx/json-c/build-sgx
JSON_SGX_LIB	:= -ljson-c-sgx
# MurMurHash
MURMUR_SRC     ?= ../murmur3
MURMUR_OBJ     := $(MURMUR_SRC)/murmur3.o
#
PICA_SRC       ?= ../src/
PICA_INCLUDE   := -I$(PICA_SRC)
PICA_LIB_PATH  := $(PICA_SRC)
PICA_LIB_SO    := pica_clnt-sgx

HOST_BIN := host
UNTRUSTED_SRCS := Host/host.c  Host/pica_poc_u.c Host/untrusted_sgx_socket.c
UNTRUSTED_OBJS := $(UNTRUSTED_SRCS:.c=.o)  $(MURMUR_OBJ) 
HOST_LDLIBS :=	-L$(PICA_LIB_PATH) -lpica_clnt-normal \
		-Wl,-rpath,$(PICA_LIB_PATH) \
		-L$(SGX_LIBRARY_PATH)  -lsgx_urts \
		-lcrypto -ljson-c \
		-L$(TSS2_LIB) -ltss2-mu -ltss2-rc \
		-L$(CBOR_LIB) -lcbor
#-lsgx_urts -lsgx_uae_service -lsgx_quote_ex  -lsgx_usgxssl -lsgx_utls -lsgx_dcap_ql -lsgx_dcap_quoteverify -lpthread -lstdc++ \
#	../tpm2/libquote.o ../tpm2/libmeasurement.o ../tpm2/libsock.o \
#	../murmur3/murmur3.o \
#	-ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc

TRUSTED_SRCS	:= Enclave/main.c Enclave/enclave.c Enclave/pica_poc_t.h
TRUSTED_OBJS	:= Enclave/main.o Enclave/enclave.o Enclave/pica_poc_t.o \
		   $(MURMUR_OBJ)
SGX_SO	:= libpica_poc.so
SGX_CONFIG	:= Enclave/pica_poc.config.xml
SGX_SIGNED	:= pica_poc.signed.so 
SGX_LDFLAGS	:= -Wl,--no-undefined -nostdlib -nodefaultlibs \
  -nostartfiles -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -lsgx_trts \
  -L$(SGX_SSLLIB_PATH) -lsgx_tsgxssl_ssl -lsgx_tsgxssl \
  -lsgx_tsgxssl_crypto \
  -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc  \
  -lsgx_tcxx \
  -lsgx_tcrypto \
  -L$(CBOR_LIB) -lcbor \
  -L$(TSS2_LIB) -ltss2-mu -ltss2-rc \
  -L$(JSON_SGX_PATH) $(JSON_SGX_LIB) \
  -L$(PICA_LIB_PATH) -l$(PICA_LIB_SO) \
  -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -lsgx_tservice \
  -Wl,--defsym=__ImageBase=0

#  -lsgx_tstdc \
#  -lcbor -L./Enclave/external/src \
#  -ltss2-mu -L../tpm2-tss/src/tss2-mu/.libs/ \
#  -ltss2-rc -L../tpm2-tss/src/tss2-rc/.libs/ \
#  -ljson-c-sgx -L./ \
#  -lgcc -L/usr/lib/gcc/x86_64-linux-gnu/11/

.PHONY: all
all: $(HOST_BIN) $(SGX_SIGNED)

$(HOST_BIN): $(UNTRUSTED_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)
$(SGX_BIN):
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)

Host/host.o: Host/host.c $(PICA_SRC)/pica_u.h
	$(CC) $(HOST_CFLAGS) $(PICA_INCLUDE) $(HOST_INCLUDE) -c $< -o $@
Host/pica_poc_u.o: Host/pica_poc_u.c Host/pica_poc_u.h
	$(CC) $(SGX_CFLAGS)  $(PICA_INCLUDE) $(SGX_EDGER_INCLUDE) $(HOST_INCLUDE) -c $< -o $@
##$(PICA_SRC)/pica_u.o: $(PICA_SRC)/pica_u.c $(PICA_SRC)/pica_u.h
##	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) $(PICA_INCLUDE) -c $< -o $@

# --- Edger8r codegen ---
Enclave/pica_poc_t.c Enclave/pica_poc_t.h: $(EDL)
	$(EDGER8R) --trusted $(EDL) \
	--search-path Enclave \
	--search-path $(PICA_SRC) \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--trusted-dir ./Enclave
Host/pica_poc_u.c Host/pica_poc_u.h: $(EDL)
	$(EDGER8R) --untrusted $(EDL) \
	--search-path Enclave \
	--search-path $(PICA_SRC) \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--untrusted-dir ./Host

#
Enclave/main.o : Enclave/main.c
	$(CC) $(SGX_CFLAGS) $(SGX_INCLUDE) $(PICA_INCLUDE) -c $< -o $@
Enclave/enclave.o : Enclave/enclave.c
	$(CC) $(SGX_CFLAGS) $(SGX_INCLUDE) $(PICA_INCLUDE) -c $< -o $@
Enclave/pica_poc_t.o: Enclave/pica_poc_t.c Enclave/pica_poc_t.h
	$(CC) $(SGX_CFLAGS) $(SGX_INCLUDE) $(PICA_INCLUDE) -c $< -o $@

# --- Enclave shared object (unsigned) ---
$(SGX_SO): $(TRUSTED_OBJS)
	$(CC) -o $@ $^ $(SGX_LDFLAGS) -Wl,-Map,server.map
# --- Sign enclave ---
$(SGX_SIGNED): $(SGX_SO) $(SGX_CONFIG)
	$(SGX_SIGN) sign -key ./Enclave/enclave_private.pem \
	  -enclave $(SGX_SO) -out $@ -config $(SGX_CONFIG) -dumpfile enclave_server.dump
#
# For Enclave signing
create_pem:
	openssl genrsa -3 -out Enclave/enclave_private.pem 3072
	openssl rsa -in Enclave/enclave_private.pem -pubout -out Enclave/enclave_public.pem

#
#
#
clean:
	rm -f *.so */*.o
