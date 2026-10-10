#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>

#include <openssl/types.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

//struct timespec;
#include "pica_t.h"
#include "libio.h"

extern char	**makeargv(int argc, int *argpos, char *buf);
extern int	main(int argc, char **argv);

/*
 * Host machine may call this file
 */
sgx_status_t e_main(int argc, int *argpos, int blen, char *buf)
{
    char	**argv;

    argv = makeargv(argc, argpos, buf);
    printf("%s: testing printf\n", __func__);
    main(argc, argv);
    return SGX_SUCCESS;
}
