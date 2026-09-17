$ git clone https://github.com/json-c/json-c.git
$ git checkout json-c-0.19-20260627
$ patch -p1 < ../json-c-sgx-enclave.patch
$ export SGX_SDK=/opt/intel/sgxsdk
$ cmake -S . -B build-sgx-config \
    -DSGX_ENCLAVE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=OFF \
    -DBUILD_TESTING=OFF
$ make -f Makefile.sgx
