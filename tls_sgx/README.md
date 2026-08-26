#
#
1) If you have not cloned this repository with "--recursive option", then
   git submoudle update --init --recursive

# Intel TLS built
# No needed ??
Intel TLS
  $ cd ./linux-sgx/SampleCode/SampleAttestedTLS
  $ cd ./linux-sgx/SampleCode/SampleAttestedTLS/sgxssl/Linux
  $ make -j  DEBUG=0 NO_THREADS=1 SGX_MODE=HW BUILD_SSL_LIB=1 -U_FORTIFY_SOURCE

  memo
    In build_openssl.sh, "-D_FORTIFY_SOURCE=2" should be removed if fprintf debug statements are needed.
  Inside Enclave
      time() is translated to sgxssl_time()

# Intel dcap libs
```sh
$ curl -fsSLo sgx_linux_x64_sdk.bin https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.30.101.1.bin
$ chmod +x sgx_linux_x64_sdk.bin
$ sudo ./sgx_linux_x64_sdk.bin --prefix /opt/intel
####
$ sudo mkdir -p /etc/apt/keyrings
$ curl -fsSLO \
	https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
$ sudo mv intel-sgx-deb.key \
	  /etc/apt/keyrings/intel-sgx-keyring.asc
### For jammy
$ echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' \
| sudo tee /etc/apt/sources.list.d/intel-sgx.list
### For noble
$ echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' \
| sudo tee /etc/apt/sources.list.d/intel-sgx.list
#### Then
$ sudo apt update
$ sudo apt install libsgx-dcap-quote-verify libsgx-dcap-quote-verify-dev
$ sudo apt install libsgx-dcap-ql libsgx-dcap-ql-dev
```

# build
2)
   $ cd Enclave/external
   $ cmake -DCMAKE_BUILD_TYPE=Release -DCBOR_PRETTY_PRINTER=OFF libcbor
   $ make
   example progm compilation will fail, but it is OK.
3) $ cd ../..; make
4)
   shell1) make run-tlsra_server
   shell2) make run-tlsra_client


#

shell4: cd tpm2/; make run-daemon


------------------------------------------------------------------------
openssl genrsa -3 -out Enclave/enclave_private.pem 3072
openssl rsa -in Enclave/enclave_private.pem -pubout -out Enclave/enclave_public.pem
