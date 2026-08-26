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


------------------------------------------------------------------------
openssl genrsa -3 -out Enclave/enclave_private.pem 3072
openssl rsa -in Enclave/enclave_private.pem -pubout -out Enclave/enclave_public.pem
