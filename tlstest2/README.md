#
#
1) If you have not cloned this repository with "--recursive option", then
   git submoudle update --init --recursive

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
