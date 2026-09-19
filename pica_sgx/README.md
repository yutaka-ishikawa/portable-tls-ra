
# prepare
$ git submodule update --init --recursive

# build
1) Build libcbor
   $ cd Enclave/external
   $ cd Enclave/external
   $ cmake -DCMAKE_BUILD_TYPE=Release -DCBOR_PRETTY_PRINTER=OFF libcbor
   $ make
   example progm compilation will fail, but it is OK.
2) Build tpm2-tss
   $ cd ../../../tpm2-tss
   $ ./bootstrap
   $ ./configure \
    --enable-static \
    --disable-shared \
    --disable-log-file \
    --with-maxloglevel=none
   $ make -j
3) Build murmur3
   $ cd ../
   $ git clone https://github.com/PeterScott/murmur3.git
   $ cd murmur3
   $ make
4) Build json-c-sgx
   $ ../json-c-sgx
   $ git clone https://github.com/json-c/json-c.git
   $ cd json-c
   $ git checkout json-c-0.19-20260627
   $ patch -p1 < ../json-c-sgx-enclave.patch
   $ export SGX_SDK=/opt/intel/sgxsdk
   $ cmake -S . -B build-sgx-config \
     -DSGX_ENCLAVE=ON \
     -DBUILD_SHARED_LIBS=OFF \
     -DBUILD_APPS=OFF \
     -DBUILD_TESTING=OFF
   $ make -f Makefile.sgx
   $ cp -p build-sgx/libjson-c-sgx.a ../../pica_sgx/
   $ cd ../..
5) Build pica_sgx
   $ cd pica_sgx
   $ make

# Configure
1) Modification of the policy.json file
   You must modify the following two lines of policy.json:
   Line 8:
       "Binary": "/home/ishikawa/work/portable-tls-ra/pica_sgx/host",
   Line 20:
        "/home/ishikawa/work/portable-tls-ra/pica_sgx/host"
# TPM evidence creation
 $ sudo ../tpm2/get_quote 
 The reg_quote.bin has been created.
# Run
1) To generate a conf file
  $ make run-pica-reg
 or
  $ make run-pica-reg2
2) Run
  $ make run-pica-exe
 or
  $ make run-pica-exe2

######################################
*********Host --> Enclave**********
start sec:(36008087) nsec(337817036)
end sec(36008087) nsec(338075808)
latency(msec): 0.258772
***********************************
*********Host --> Enclave**********
start sec:(36008161) nsec(223333339)
end sec(36008161) nsec(506177677)
latency(msec): 282.844330
***********************************
