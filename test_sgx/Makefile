SGX_MODE = HW
MY_SEARCHPATH = --search-path /home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgx_socket/include/ \
--search-path /home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/Linux/package/include/

MYCOPTION = -DSGX_ENCLAVE -DOPENSSL_DEV_NO_ATOMICS
MYINCLUDE = -I/opt/intel/sgxssl/include \
	-I../src/ \
	-I/home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgx_socket/include \
	-I/home/ishikawa/work/linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/openssl_source/openssl-3.0.13/include

#-I/opt/intel/sgxsdk/SampleCode/SampleAttestedTLS/sgx_socket/include \
#-I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/openssl_source/openssl-3.1.6/include/ \
#	-I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/openssl_source/openssl-3.1.6/
##	-I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/Linux/package/include
#	-I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/Linux/sgx/fips_test/trusted/ \
#	-I/home/ishikawa/work/linux-sgx/external/dcap_source/QuoteVerification/sgxssl/openssl_source/openssl-3.1.6-source-fips
#
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
HOST_LDLIBS := -L$(SGX_LIBRARY_PATH) -L$(SGX_MYDCAPLIBRARY_PATH) -L$(SGX_MYHOSTLIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lsgx_quote_ex  -lsgx_usgxssl -lsgx_utls -lsgx_dcap_ql -lsgx_dcap_quoteverify -lcrypto -lpthread -lstdc++
###HOST_CFLAGS := -O2 -g $(SGX_INCLUDE)
HOST_CFLAGS := -O2 -g $(SGX_HOSTINCLUDE)
HOST_LDFLAGS :=

# Enclave libs
ENCLAVE_TRUSTED_CFLAGS := -O2 -g -nostdinc -fvisibility=hidden -fPIC \
  -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
  -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/epid \
  $(MYINCLUDE) $(MYCOPTION) \
  -fno-builtin-printf -fno-builtin-perror

#ENCLAVE_TRUSTED_LDFLAGS := -Wl,--no-undefined -nostdlib -nodefaultlibs \
#  -nostartfiles -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -lsgx_trts \
#  -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx \
#  -lsgx_tcxx -lsgx_tcrypto -Wl,--end-group \
#  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
#  -Wl,-z,relro,-z,now,-z,noexecstack \
#  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic

#  -L$(SGX_MYSSL_PATH) -lssl -lcrypto
#  -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc
##
ENCLAVE_TRUSTED_LDFLAGS := -Wl,--no-undefined -nostdlib -nodefaultlibs \
  -nostartfiles -L$(SGX_LIBRARY_PATH) -Wl,--whole-archive -lsgx_trts \
  -L$(SGX_MYSSL_PATH) -lsgx_tsgxssl_ssl -lsgx_tsgxssl \
  -lsgx_tsgxssl_crypto \
  -Wl,--no-whole-archive -Wl,--start-group -lsgx_tstdc  \
  -lsgx_tcxx \
  -lsgx_tcrypto -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -lsgx_tservice \
  -Wl,--defsym=__ImageBase=0

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

# ==== Files ====
EDL := Enclave/Enclave.edl
TRUSTED_SRCS := Enclave/enclave.c Enclave/libtlsra.c Enclave/libsock.c Enclave/tlsra_server.c Enclave/Enclave_t.c
TRUSTED_OBJS := $(TRUSTED_SRCS:.c=.o)

UNTRUSTED_SRCS := Host/host.c Host/untrusted_sgx_socket.c Enclave/Enclave_u.c
UNTRUSTED_OBJS := $(UNTRUSTED_SRCS:.c=.o)

ENCLAVE_SO := enclave.so
ENCLAVE_SIGNED := enclave.signed.so
ENCLAVE_CONFIG := Enclave/enclave.config.xml

HOST_BIN := host

# ==== Rules ====
.PHONY: all run clean distclean

all: $(HOST_BIN) $(ENCLAVE_SIGNED)

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
$(ENCLAVE_SO): $(TRUSTED_OBJS)
	$(CC) -o $@ $^ $(ENCLAVE_TRUSTED_LDFLAGS)

# --- Sign enclave ---
$(ENCLAVE_SIGNED): $(ENCLAVE_SO) $(ENCLAVE_CONFIG)
	$(SGX_SIGN) sign -key ./Enclave/enclave_private.pem \
	  -enclave $(ENCLAVE_SO) -out $@ -config $(ENCLAVE_CONFIG) -dumpfile enclave.dump

# --- Host objects ---
Host/host.o: Host/host.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) -I./Enclave/ -c $< -o $@
Host/%.o: Host/%.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) -I./Enclave/ -c $< -o $@

# --- Host binary ---
$(HOST_BIN): $(UNTRUSTED_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)

# --- Convenience ---
run-tlsra_server:
	./host -p 10101 -V -v -r

clean:
	$(RM) $(TRUSTED_OBJS) $(UNTRUSTED_OBJS) $(ENCLAVE_SO) $(ENCLAVE_SIGNED) $(HOST_BIN) enclave.dump quote.bin

distclean: clean
	$(RM) Enclave/Enclave_t.* Enclave/Enclave_u.*
