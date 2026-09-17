
# prepare
$ git submodule update --init --recursive

# build
1) Build libcbor
   $ cd Enclave/external
   $ cd Enclave/external
   $ cmake -DCMAKE_BUILD_TYPE=Release -DCBOR_PRETTY_PRINTER=OFF libcbor
   $ make
   #example progm compilation will fail, but it is OK.
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
4) $ cd pica_sgx

