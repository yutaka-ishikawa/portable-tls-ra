#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

#define ENCLAVE_FILE "./enclave_client.signed.so"

static float
time_to_msec(int64_t st_sec, int64_t st_nsec, int64_t et_sec, int64_t et_nsec)
{
    int64_t sec = et_sec - st_sec;
    int64_t nsec = et_nsec - st_nsec;
    double msec;
    printf("sec(%f) nsec(%f)\n", (float) sec, (float) nsec);
    msec = (((double)sec*1000) + (double)(nsec)/(double)1000000);
    return (float) msec;
}

static void
getclocktime(int64_t *sec, int64_t *nsec)
{
    ocall_getclocktime(sec, nsec);
}

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
    int64_t	st_sec, st_nsec, et_sec, et_nsec;

    printf("***** Host *****\n(%s)\n", get_current_dir_name());
    ENCLAVE_CALL(err0, rc,
		 sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
				    &tok, &updated, &eid, NULL),
		 "sgx_create_enclave failed: 0x%x\n", rc);
    //getoption(argc, argv);
    makeargs(argc, argv, &argpos, &bp, &blen);

    getclocktime(&st_sec, &st_nsec);
    ENCLAVE_CALL(err1, rc,
		 e_main(eid, &erc, argc, argpos, blen, bp),
		 "e_mail invocation failed: 0x%x\n", rc);
    getclocktime(&et_sec, &et_nsec);
    {
	double lat = time_to_msec(st_sec, st_nsec, et_sec, et_nsec);
	printf("*********Host --> Enclave**********\n");
	printf("start sec:(%ld) nsec(%ld)\n", st_sec, st_nsec);
	printf("end sec(%ld) nsec(%ld)\n", et_sec, et_nsec);
	printf("latency(msec): %f\n", lat);
	printf("***********************************\n");
    }

    
    if (erc != 0) {
        fprintf(stderr, "e_main failed: 0x%x\n", erc);
    }
err1:
    sgx_destroy_enclave(eid);
err0:
    return erc;
}
