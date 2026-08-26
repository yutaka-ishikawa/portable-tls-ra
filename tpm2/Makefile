CFLAGS = -MMD -Wall -g -O2
INCL = 
LIBS =  -ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc -lcrypto -lcbor
SRCS  = $(wildcard *.c)
OBJS  = $(SRCS_COMMON:.c=.o)
DEPS  = $(SRCS_COMMON:.c=.d)

MYLIBS = libquote.o libsock.o libmeasurement.o
MYCMDS = tpmdaemon test_tpmd test_quote test_libsock measure sealtest

################################
### SGX
################################
SGX_SDK ?= /opt/intel/sgxsdk
EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN:= $(SGX_SDK)/bin/x64/sgx_sign

SGX_MODE ?= SIM  # SIM or HW
# ===== Enclave =====
T_INC = -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
T_CFLAGS = -O2 -g -nostdinc -fvisibility=hidden -fPIC -DNDEBUG $(T_INC)
ifeq ($(SGX_MODE),SIM)
  T_CFLAGS += -DSGX_SIM
  TRTS  = -lsgx_trts_sim
  TSVC  = -lsgx_tservice_sim
else
  TRTS  = -lsgx_trts
  TSVC  = -lsgx_tservice
endif
ENCL_LINK = -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
  -L$(SGX_SDK)/lib64 \
  -Wl,--whole-archive $(TRTS) -Wl,--no-whole-archive \
  -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto $(TSVC) -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -Wl,--defsym=__ImageBase=0
# ===== Host =====
U_INC = -I$(SGX_SDK)/include
U_CFLAGS = -O2 -g $(U_INC)
ifeq ($(SGX_MODE),SIM)
  URTS = -lsgx_urts_sim
else
  URTS = -lsgx_urts
endif
################################
ENC_SRC = Enclave/Enclave_t.c Enclave/Enclave_u.c Enclave/enclave.c
ENC_SO  = Enclave/enclave.signed.so
#
#
#
#all: quote_esys libquote.o test_quote
all: $(MYLIBS) $(MYCMDS) Enclave/enclave.signed.so

Enclave/Enclave_t.c Enclave/Enclave_t.h Enclave/Enclave_u.c Enclave/Enclave_u.h: Enclave/Enclave.edl
	$(EDGER8R) --trusted Enclave/Enclave.edl --search-path $(SGX_SDK)/include --trusted-dir Enclave
	$(EDGER8R) --untrusted Enclave/Enclave.edl --search-path $(SGX_SDK)/include --untrusted-dir Enclave

# Enclave objects
Enclave/enclave.o: Enclave/enclave.c Enclave/Enclave_u.h
	$(CC) $(T_CFLAGS) $(T_INC) -c $< -o $@

Enclave/Enclave_u.o: Enclave/Enclave_u.c Enclave/Enclave_u.h
	$(CC) $(T_CFLAGS) $(T_INC) -c $< -o $@

Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
	$(CC) $(T_CFLAGS) $(U_INC) -c $< -o $@

enclave.so: Enclave/enclave.o Enclave/Enclave_t.o
	$(CC) -o $@ $^ $(ENCL_LINK)
# Making Sign Key
Enclave/enclave_private.pem:
	openssl genrsa -3 -out $@ 3072

# Signing
Enclave/enclave.signed.so: enclave.so Enclave/Enclave.config.xml Enclave/enclave_private.pem
	$(SGX_SIGN) sign -key Enclave/enclave_private.pem \
	  -enclave enclave.so -out $@ -config Enclave/Enclave.config.xml

tpmdaemon: tpmdaemon.o libquote.o libsock.o libmeasurement.o Enclave/Enclave_u.o
	cc $(CFLAGS) $(U_INC) -o $@ $^ $(LIBS) $(URTS)
tpmdaemon.o: tpmdaemon.c
	cc $(CFLAGS) $(U_INC) -c $@ $^ $(LIBS)
test_tpmd: test_tpmd.o libquote.o libsock.o libmeasurement.o
	cc $(CFLAGS) -o $@ $^ $(LIBS)
test_quote: libquote.c
	cc $(CFLAGS) -DLIBQUOTE_TEST -o $@ $^ $(LIBS)
test_libsock: libsock.c libsock.h
	cc $(CFLAGS) -DLIBSOCK_TEST -o $@ libsock.c
measure: libmeasurement.c
	cc $(CFLAGS) -DCMD_MEASURE -o $@ $^ -lcrypto
sealtest: sealtest.o  Enclave/Enclave_u.o
	cc $(CFLAGS) $(U_INC) -o $@ $^ $(LIBS) $(URTS)
sealtest.o: sealtest.c
	cc $(CFLAGS) $(U_INC) -c $@ $^ $(LIBS)
quote_esys: quote_esys.c
	cc $(CFLAGS) -o $@ $^ $(LIBS)

run-daemon:
	sudo ./tpmdaemon /tmp/sock-tpmd-daemon
run-sealtest:
	echo "Hello world" >plain.txt
	./sealtest -s -i ./plain.txt -o ./cipher.txt
	./sealtest -u -i ./cipher.txt
clean:
	rm -f $(MYLIBS) $(MYCMDS) Host/*.o Enclave/*.o Enclave/*.so
depend:

-include $(DEPS)
