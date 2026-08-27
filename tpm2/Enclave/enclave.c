/*
 *	seal/unseal: no MAC
 */
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "Enclave_t.h"

int
printf(const char *fmt, ...)
{
    char	*bp = NULL;
    size_t	len = 0;
    va_list arg;
    /* determine required size */
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    len++;
    bp = malloc(len);
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    ocall_print(bp);
    free(bp);
}

int
puts(char *str)
{
    ocall_print(str);
    ocall_print("\n");
}

sgx_status_t
ecall_seal(uint32_t len_dat, const uint8_t *datp,
	   uint32_t len_out, uint8_t *outp, uint32_t *encsz)
{
    uint32_t	enclen;
    sgx_sealed_data_t 	*encbufp;
    sgx_status_t  err;
    
    //printf("%s: len_dat=%d len_out=%d\n", __func__, len_dat, len_out);
    *encsz = 0;
    enclen = sgx_calc_sealed_data_size(0, len_dat);
    printf("%s enclen=%d\n", __func__, enclen);
    encbufp = (sgx_sealed_data_t*) malloc(enclen);
    if(encbufp == NULL) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    err = sgx_seal_data(0, NULL, len_dat, datp, enclen, encbufp);
    #if 0
    {
	sgx_attributes_t attr_mask = SGX_ATTRIBUTES_DEFAULT_MASK;
	err = sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER, attr_mask,
			       TSEAL_DEFAULT_MISCMASK, 0, NULL,
			       len_dat, datp, enclen, encbufp);
    }
#endif
    if (err == SGX_SUCCESS)  {
        memcpy(outp, encbufp, enclen);
	*encsz = enclen;
    } else {
	printf("%s: ERROR!!!!!! err(%d)\n", __func__, err);
    }
    free(encbufp);
    return err;
}

sgx_status_t
ecall_unseal(uint32_t len_dat, const uint8_t *datp,
	     uint32_t len_out, uint8_t *outp, uint32_t *plsz)
{
    uint32_t	dlen;
    uint8_t	*decdata;
    sgx_status_t st;

    printf("%s: len_dat=%d len_out=%d\n", __func__, len_dat, len_out);

    dlen = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)datp);
    decdata = (uint8_t *) malloc(dlen);
    if(decdata == NULL) {
        st = SGX_ERROR_OUT_OF_MEMORY;
	goto err1;
    }
    st = sgx_unseal_data((const sgx_sealed_data_t *) datp,
			 NULL, 0, decdata, &dlen);
    printf("%s: dlen = %d\n", __func__, dlen);
    if (st != SGX_SUCCESS) goto err0;
    memcpy(outp, decdata, dlen);
    *plsz = dlen;
err0:
    free(decdata);
err1:
    return st;
}
