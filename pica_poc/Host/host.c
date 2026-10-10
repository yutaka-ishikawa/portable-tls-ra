#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sgx_urts.h>
#include <pica_u.h>
#include <pica_poc_u.h>

extern void	getclocktime(int64_t *sec, int64_t *nsec);
extern float	time_to_msec(int64_t st_sec, int64_t st_nsec, int64_t et_sec, int64_t et_nsec);
extern int	makeargs(int argc, char **argv, int **argpos, char **buf, int *buflen);

int	vflag = 0;
int	oflag = 0;

#define ENCLAVE_CALL(label, val, lib, fmt, ...)	\
do {				\
    val = lib;			\
    if (val != SGX_SUCCESS) {	\
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	goto label;		\
    }				\
} while(0)

#define ENCLAVE_FILE "./pica_poc.signed.so"

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
