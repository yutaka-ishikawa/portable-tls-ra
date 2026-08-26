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
	-I/usr/include/tss2

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
  -Wl,--defsym=__ImageBase=0 \
  -lcbor -L./Enclave/external/src

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
TRUSTED_SERVER_SRCS := Enclave/enclave_server.c Enclave/libtlsra.c Enclave/libsock.c Enclave/tlsra_server.c Enclave/Enclave_t.c Enclave/libcert.c Enclave/libintel.c Enclave/libtpm2.c Enclave/libtpm2.c
TRUSTED_SERVER_OBJS := $(TRUSTED_SERVER_SRCS:.c=.o)
TRUSTED_CLIENT_SRCS := Enclave/enclave_client.c Enclave/libtlsra.c Enclave/libsock.c Enclave/tlsra_client.c Enclave/Enclave_t.c Enclave/libcert.c Enclave/libintel.c Enclave/libtpm2.c
TRUSTED_CLIENT_OBJS := $(TRUSTED_CLIENT_SRCS:.c=.o)

UNTRUSTED_SERVER_SRCS := Host/host_server.c Host/host_lib.c Host/untrusted_sgx_socket.c Enclave/Enclave_u.c Host/tpm2.c
UNTRUSTED_SERVER_OBJS := $(UNTRUSTED_SERVER_SRCS:.c=.o)
UNTRUSTED_CLIENT_SRCS := Host/host_client.c Host/host_lib.c Host/untrusted_sgx_socket.c Enclave/Enclave_u.c Host/tpm2.c
UNTRUSTED_CLIENT_OBJS := $(UNTRUSTED_CLIENT_SRCS:.c=.o)

ENCLAVE_SERVER_SO := enclave_server.so
ENCLAVE_SERVER_SIGNED := enclave_server.signed.so
ENCLAVE_SERVER_CONFIG := Enclave/enclave_server.config.xml

ENCLAVE_CLIENT_SO := enclave_client.so
ENCLAVE_CLIENT_SIGNED := enclave_client.signed.so
ENCLAVE_CLIENT_CONFIG := Enclave/enclave_client.config.xml

HOST_SERVER_BIN := host_server
HOST_CLIENT_BIN := host_client

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
Host/host_server.o: Host/host_server.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) -I./Enclave/ -c $< -o $@
Host/host_client.o: Host/host_client.c Enclave/Enclave_u.h
	$(CC) $(HOST_CFLAGS) $(SGX_INCLUDE) -I./Enclave/ -c $< -o $@
Host/%.o: Host/%.c Enclave/Enclave_u.h Host/host.h
	$(CC) $(HOST_CFLAGS) -I./Enclave/ -c $< -o $@

# --- Host binary ---
$(HOST_SERVER_BIN): $(UNTRUSTED_SERVER_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)
$(HOST_CLIENT_BIN): $(UNTRUSTED_CLIENT_OBJS)
	$(CC) -o $@ $^ $(HOST_LDFLAGS) $(HOST_LDLIBS)

#
# Ore Ore CA
#	
oreore:
	@echo "***** Creating CA"
	mkdir -p ./CA
	openssl genrsa -out ./CA/my_ca.key 2048
	openssl req -x509 -new -nodes -key ./CA/my_ca.key -sha256 -days 3650 -out ./CA/my_ca.crt \
	-subj "/C=JP/ST=Tokyo/L=Chiyoda/O=ROIS/OU=CRADSEC/CN=cradsec-ca.rois.ac.jp"
	c_rehash ./CA/
#
#	server.key RSA
#	server.csr サーバ証明書要求ファイル
#	server.crt サーバ証明書 signed by ./CA/my_ca.crt
	@echo "***** Server Certificate"
	openssl genrsa -out ./server.key 2048
	openssl req -new -key ./server.key -out ./server.csr \
	-subj "/C=JP/ST=Tokyo/L=Chiyoda/O=ROIS/OU=CRADSEC/CN=cradsec-server.rois.ac.jp"
	openssl x509 -req -in ./server.csr -CA ./CA/my_ca.crt -CAkey ./CA/my_ca.key -CAcreateserial -out ./server.crt -days 365 -sha256

#
# self-signed certificate
#	public.key is a cert file
#	private.key is its private key
certgg:
	openssl req -new -x509 -nodes -out public.key -keyout private.key

#
#
run-tlsra_server:
#	./host -p 10101 -V -v -r
#	./host_server -V -r
	../tpm2/measure -o ./measure_server.bin ./host_server
	./host_server -V -r
run-tlsra_server-D:
	../tpm2/measure -o ./measure_server.bin ./host_server
	./host_server -V -v -r -D /tmp/sock-tpmd-daemon
trace-run-tlsra_server:
	strace -f -o ./trace-server.txt ./host_server -V -v -r -O
run-tlsra_client:
	../tpm2/measure -o ./measure_client.bin ./host_client
	./host_client -d
run-tlsra_client-D:
	../tpm2/measure -o ./measure_client.bin ./host_client
#	./host_client -d -D /tmp/sock-tpmd-daemon
	./host_client -D /tmp/sock-tpmd-daemon
trace-run-tlsra_client:
	strace -f -o ./trace-client.txt ./host_client -d -O
#
#
extract-server-trace:
	grep openat ./trace-server.txt > trace-server-openat.txt
	awk -F'"' '/openat\(/ {print $$2}' trace-server-openat.txt > server-openfile.txt


clean:
	$(RM) $(TRUSTED_SERVER_OBJS) $(UNTRUSTED_SERVER_OBJS) \
	 $(TRUSTED_CLIENT_OBJS) $(UNTRUSTED_CLIENT_OBJS) \
	$(ENCLAVE_SERVER_SO) $(ENCLAVE_SERVER_SIGNED) $(HOST_SERVER_BIN) \
	$(ENCLAVE_CLIENT_SO) $(ENCLAVE_CLIENT_SIGNED) $(HOST_CLIENTm_BIN) \
	enclave_server.dump enclave_client.dump quote.bin

distclean: clean
	$(RM) Enclave/Enclave_t.* Enclave/Enclave_u.*
