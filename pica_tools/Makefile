PICA_SRC	?= ../src/
MURMUR3_INCPATH ?= ../murmur3/
SGX_SDK		?= /opt/intel/sgxsdk

EDGER8R		:= $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_EDGER_INCLUDE := -I$(SGX_SDK)/include
SGX_SIGN	:= $(SGX_SDK)/bin/x64/sgx_sign
EDL		:= toollib.edl
SGX_SO		:= toollib.so
TRUSTED_OBJS	:= toollib_t.o sgxtoollib.o
SGX_SIGNED	:= toollib.signed.so
SGX_CONFIG	:= toollib.config.xml

SGX_LINUX-SGX	?= /home/ishikawa/work/linux-sgx/
SGX_SSL		:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/
SGX_SOCKET	:= $(SGX_LINUX-SGX)/SampleCode/SampleAttestedTLS/sgx_socket/

PICA_INCLUDE	:= $(PICA_SRC)
PICA_LIB_PATH	:= $(PICA_SRC)
PICA_LIB_SO    := pica_clnt-sgx

SGX_ENCL_KEY	:= ../pica_poc/Enclave/enclave_private.pem
SGX_INCLUDES	:= -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SOCKET)/include  -I$(SGX_SSL)/include
SGX_CFLAGS	:= -Wall -g -O2 -c -DSGXENV
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_SSLLIB_PATH := $(SGX_SSL)/lib64
CFLAGS		:= -Wall -g -O2 -c
INCLUDES	:= -I$(MURMUR3_INCPATH) -I$(PICA_INCLUDE) -I$(SGX_SDK)/include

TSS2_INSTALL	?= ../external/
TSS2_INCPATH	:= $(TSS2_INSTALL)/include/tss2
TSS2_LIB	:= $(TSS2_INSTALL)/lib
JSON_SGX_PATH	?= ../json-c-sgx/json-c/build-sgx
JSON_SGX_LIB	:= -ljson-c-sgx
CBOR_INSTALL	?= ../external/
CBOR_LIB	:= $(CBOR_INSTALL)/lib
CBOR_INCPATH	:= $(CBOR_INSTALL)/include

MURMUR_SRC     ?= ../murmur3
MURMUR_OBJ     := $(MURMUR_SRC)/murmur3.o

UNTRUSTED_OBJS	:=  $(MURMUR_OBJ) untrusted_sgx_socket.o
HOST_LDLIBS :=	-L$(PICA_LIB_PATH) -lpica_clnt-normal \
		-Wl,-rpath,$(PICA_LIB_PATH) \
		-L$(SGX_LIBRARY_PATH)  -lsgx_urts \
		-lcrypto -ljson-c \
		-L$(TSS2_LIB) -ltss2-mu -ltss2-rc \
		-L$(CBOR_LIB) -lcbor


SGX_LDFLAGS	:= -Wl,--no-undefined -nostdlib -nodefaultlibs \
  -nostartfiles -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -lsgx_trts \
  -L$(SGX_SSLLIB_PATH) \
  -Wl,--no-whole-archive \
  -Wl,--start-group \
  -lsgx_tservice \
  -lsgx_tcrypto \
  -lsgx_tstdc  \
  -lsgx_tcxx \
  -lsgx_tsgxssl_ssl -lsgx_tsgxssl \
  -lsgx_tsgxssl_crypto \
  -L$(CBOR_LIB) -lcbor \
  -L$(TSS2_LIB) -ltss2-mu -ltss2-rc \
  -L$(JSON_SGX_PATH) $(JSON_SGX_LIB) \
  -L$(PICA_LIB_PATH) -l$(PICA_LIB_SO) \
  -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -Wl,--defsym=__ImageBase=0


all: $(SGX_SIGNED) conftool toollib_t.o toollib_u.o
conftool: conftool.o toollib_u.o $(UNTRUSTED_OBJS)
	$(CC) -o $@ $^  $(HOST_LDLIBS) 
conftool.o: conftool.c
	$(CC)  $(INCLUDES) -c $^

# --- Edger8r codegen ---
toollib_t.c toollib_t.h: $(EDL)
	$(EDGER8R) --trusted $(EDL) \
	--search-path ./ \
	--search-path $(PICA_SRC) \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--trusted-dir ./
toollib_u.c toollib_u.h: $(EDL)
	$(EDGER8R) --untrusted $(EDL) \
	--search-path ./ \
	--search-path $(PICA_SRC) \
	--search-path $(SGX_SDK)/include \
	--search-path $(SGX_SSL)/include \
	--search-path $(SGX_SOCKET)/include \
	--untrusted-dir ./
toollib_u.o : toollib_u.c toollib_u.h
	$(CC) $(CFLAGS) $(INCLUDES)  -c $< -o $@
untrusted_sgx_socket.o: untrusted_sgx_socket.c
	$(CC) $(CFLAGS) $(INCLUDES)  -c $< -o $@
toollib_t.o:  toollib_t.c toollib_t.h
	$(CC) $(SGX_CFLAGS) $(SGX_INCLUDES) -c $< -o $@
sgxtoollib.o: sgxtoollib.c toollib_t.h
	$(CC) $(SGX_CFLAGS) $(SGX_INCLUDES) -I$(PICA_INCLUDE) -c $< -o $@

# --- Enclave shared object (unsigned) ---
$(SGX_SO): $(TRUSTED_OBJS)
	$(CC) -o $@ $^ $(SGX_LDFLAGS) -Wl,-Map,server.map
# --- Sign enclave ---
$(SGX_SIGNED): $(SGX_SO) $(SGX_CONFIG)
	$(SGX_SIGN) sign -key $(SGX_ENCL_KEY) \
	  -enclave $(SGX_SO) -out $@ -config $(SGX_CONFIG) -dumpfile enclave_server.dump

.c.o:
	$(CC) -c -g -O2 -MMD -Wall -fPIC $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.o *.so
