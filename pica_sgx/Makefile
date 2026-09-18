SGX_MODE = HW
MY_SEARCHPATH = --search-path /home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgx_socket/include/ \
--search-path /home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/include/

#MYCOPTION = -DSGX_ENCLAVE -DOPENSSL_DEV_NO_ATOMICS
MYCOPTION = -DSGX_ENCLAVE_WITH_TPM2 -DOPENSSL_DEV_NO_ATOMICS
#
# Enclave/XXX is for cbor
MYINCLUDE = -I/opt/intel/sgxssl/include \
	-I../src/ \
	-I/home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgx_socket/include \
	-I/home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/openssl_source/openssl-3.0.13/include \
	-I./Enclave/external -I./Enclave/external/src -I./Enclave/external/libcbor/src \
	-I/usr/include/tss2 \
	-I/usr/include/json-c

# ==== User-configurable ====
# SGX SDK path. If not set, try common default.
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW      # HW or SW (simulation)
SGX_DEBUG ?= 1      # 1: debug, 0: release

# ==== Toolchain / tools ====
CC := gcc
CXX := g++
AR := ar
RM := rm -f
MKDIR := mkdir -p

EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign

# ==== Common paths ====
SGX_INCLUDE := -I$(SGX_SDK)/include -I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/dcap_quoteverify/inc/ -I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteGeneration/quote_wrapper/ql/inc/
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

SGX_HOSTINCLUDE = -I$(SGX_SDK)/include

SGX_MYDCAPLIBRARY_PATH=/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteGeneration/build/linux
SGX_MYHOSTLIBRARY_PATH=/home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/lib64

SGX_MYSSL_PATH := /home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/lib64

# Host libs (DCAP)
HOST_LDLIBS := -L$(SGX_LIBRARY_PATH) -L$(SGX_MYDCAPLIBRARY_PATH) -L$(SGX_MYHOSTLIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lsgx_quote_ex  -lsgx_usgxssl -lsgx_utls -lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto -lpthread -lstdc++ \
	../tpm2/libquote.o ../tpm2/libmeasurement.o ../tpm2/libsock.o \
	-ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc
###HOST_CFLAGS := -O2 -g $(SGX_INCLUDE)
HOST_CFLAGS := -O2 -g $(SGX_HOSTINCLUDE)
HOST_LDFLAGS :=

# Enclave libs
ENCLAVE_TRUSTED_CFLAGS := -O2 -g -nostdinc -fvisibility=hidden -fPIC \
  -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
  -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/epid \
  $(MYINCLUDE) $(MYCOPTION) \
  -fno-builtin-printf -fno-builtin-perror

ENCLAVE_TRUSTED_LDFLAGS := -Wl,--no-undefined -nostdlib -nodefaultlibs \
  -nostartfiles -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -lsgx_trts \
  -L$(SGX_MYSSL_PATH) -lsgx_tsgxssl_ssl -lsgx_tsgxssl \
  -lsgx_tsgxssl_crypto \
  -lsgx_tstdc \
  -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc  \
  -lsgx_tcxx \
  -lsgx_tcrypto -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -lsgx_tservice \
  -Wl,--defsym=__ImageBase=0 \
  -lcbor -L./Enclave/external/src \
  -ltss2-mu -L../tpm2-tss/src/tss2-mu/.libs/ \
  -ljson-c-sgx -L./ \
  -lgcc -L/usr/lib/gcc/x86_64-linux-gnu/11/

ifeq ($(SGX_MODE),HW)
  ENCLAVE_DEFS := -DSGX_HW
else
  ENCLAVE_DEFS := -DSGX_SIM
endif

ifeq ($(SGX_DEBUG),1)
  ENCLAVE_DEFS += -DDEBUG
  SGX_SIGN_MODE := debug
else
  ENCLAVE_DEFS += -DNDEBUG
  SGX_SIGN_MODE := prerelease
endif

## YI
ENCLAVE_DEFS += -DSGXENV

# ==== Files ====
EDL := Enclave/Enclave.edl
TRUSTED_CLIENT_SRCS := Enclave/enclave.c Enclave/Enclave_t.c Enclave/libpica.c Enclave/picatest.c
TRUSTED_CLIENT_OBJS := $(TRUSTED_CLIENT_SRCS:.c=.o) ../murmur3/murmur3.o

UNTRUSTED_CLIENT_SRCS := Host/host.c Host/host_lib.c Host/untrusted_sgx_socket.c Enclave/Enclave_u.c Host/tpm2.c
UNTRUSTED_CLIENT_OBJS := $(UNTRUSTED_CLIENT_SRCS:.c=.o)

ENCLAVE_CLIENT_SO := enclave_client.so
ENCLAVE_CLIENT_SIGNED := enclave_client.signed.so
ENCLAVE_CLIENT_CONFIG := Enclave/enclave_client.config.xml

HOST_CLIENT_BIN := host

# ==== Rules ====
.PHONY: all run clean distclean

all: $(HOST_SERVER_BIN) $(ENCLAVE_SERVER_SIGNED) $(HOST_CLIENT_BIN)  $(ENCLAVE_CLIENT_SIGNED)

# --- Edger8r codegen ---
Enclave/Enclave_t.c Enclave/Enclave_t.h: $(EDL)
	@echo "[EDGER8R] generating trusted code"
	$(EDGER8R) --trusted $(EDL) --search-path Enclave --search-path $(SGX_SDK)/include $(MY_SEARCHPATH) \
		--trusted-dir Enclave

Enclave/Enclave_u.c Enclave/Enclave_u.h: $(EDL)
	@echo "[EDGER8R] generating untrusted code"
	$(EDGER8R) --untrusted $(EDL) --search-path Enclave --search-path $(SGX_SDK)/include $(MY_SEARCHPATH) \
		--untrusted-dir Enclave

# --- Enclave objects ---
Enclave/Enclave_u.o: Enclave/Enclave_u.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) -I./Enclave/ -c $< -o $@
Enclave/%.o: Enclave/%.c Enclave/Enclave_t.h
	$(CC) $(ENCLAVE_TRUSTED_CFLAGS) $(ENCLAVE_DEFS) -include sgx_uae_service.h -c $< -o $@

# --- Enclave shared object (unsigned) ---
$(ENCLAVE_SERVER_SO): $(TRUSTED_SERVER_OBJS)
	$(CC) -o $@ $^ $(ENCLAVE_TRUSTED_LDFLAGS) -Wl,-Map,server.map
$(ENCLAVE_CLIENT_SO): $(TRUSTED_CLIENT_OBJS)
	$(CC) -o $@ $^ $(ENCLAVE_TRUSTED_LDFLAGS) -Wl,-Map,client.map

# --- Sign enclave ---
$(ENCLAVE_SERVER_SIGNED): $(ENCLAVE_SERVER_SO) $(ENCLAVE_CONFIG)
	$(SGX_SIGN) sign -key ./Enclave/enclave_private.pem \
	  -enclave $(ENCLAVE_SERVER_SO) -out $@ -config $(ENCLAVE_SERVER_CONFIG) -dumpfile enclave_server.dump
$(ENCLAVE_CLIENT_SIGNED): $(ENCLAVE_CLIENT_SO) $(ENCLAVE_CONFIG)
	$(SGX_SIGN) sign -key ./Enclave/enclave_private.pem \
	  -enclave $(ENCLAVE_CLIENT_SO) -out $@ -config $(ENCLAVE_CLIENT_CONFIG) -dumpfile enclave_client.dump

# --- Host objects ---
Host/host.o: Host/host.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) -I./Enclave/ -c $< -o $@
Host/%.o: Host/%.c Enclave/Enclave_u.h Host/host.h
	$(CC) $(HOST_CFLAGS) -I./Enclave/ -c $< -o $@

# --- Host binary ---
$(HOST_SERVER_BIN): $(UNTRUSTED_SERVER_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)
$(HOST_CLIENT_BIN): $(UNTRUSTED_CLIENT_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)

#
# Test programs
#
showconf: showconf.c Enclave/libpica.c
	cc -I/usr/include/json-c  -g -O2 -o showconf showconf.c Enclave/libpica.c ../murmur3/murmur3.o -ljson-c

#
#
#
run-pica-reg:
	./host -r pica.conf -D /tmp/sock-tpmd-daemon
run-pica-reg2:
	./host -r pica.conf -D /tmp/sock-tpmd-daemon2
run-pica-exe:
	./host -D 
#
#
clean:
	$(RM) $(TRUSTED_SERVER_OBJS) $(UNTRUSTED_SERVER_OBJS) \
	 $(TRUSTED_CLIENT_OBJS) $(UNTRUSTED_CLIENT_OBJS) \
	$(ENCLAVE_SERVER_SO) $(ENCLAVE_SERVER_SIGNED) $(HOST_SERVER_BIN) \
	$(ENCLAVE_CLIENT_SO) $(ENCLAVE_CLIENT_SIGNED) $(HOST_CLIENTm_BIN) \
	enclave_server.dump enclave_client.dump quote.bin

distclean: clean
	$(RM) Enclave/Enclave_t.* Enclave/Enclave_u.*
