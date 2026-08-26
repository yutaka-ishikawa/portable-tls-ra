#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
/* for network */
#include <sys/socket.h>
//#include <sys/un.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
/**/
#include "host.h"

#include <sgx_urts.h>
#include <sgx_uae_service.h>	/* sgx_target_info_t might be defined */
#include <sgx_ql_quote.h>          // DCAP: QE target info / quote APIs
#include <sgx_dcap_quoteverify.h>  // (任意) 検証APIを使うなら
#include <sgx_dcap_ql_wrapper.h>   // added YI
#include "Enclave_u.h"

#define ENCLAVE_FILE "./enclave_server.signed.so"

int
main(int argc, char** argv)
{
    int		*argpos;
    char	*bp;
    int		blen;
    sgx_enclave_id_t	eid = 0;
    sgx_launch_token_t	tok = {0};
    int updated = 0;
    sgx_status_t	rc;
    sgx_status_t	erc = -1;

    printf("***** Server *****\n(%s)\n", get_current_dir_name());
    ENCLAVE_CALL(err0, rc,
		 sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
				    &tok, &updated, &eid, NULL),
		 "sgx_create_enclave failed: 0x%x\n", rc);
    getoption(argc, argv);
    makeargs(argc, argv, &argpos, &bp, &blen);
    ENCLAVE_CALL(err1, rc,
		 e_main(eid, &erc, argc, argpos, blen, bp),
		 "e_mail invocation failed: 0x%x\n", rc);
    if (erc != 0) {
        fprintf(stderr, "e_main failed: 0x%x\n", erc);
    }
err1:
    sgx_destroy_enclave(eid);
err0:
    return erc;
}
