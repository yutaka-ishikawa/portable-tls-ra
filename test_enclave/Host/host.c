#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_urts.h>
#include <sgx_uae_service.h>	/* sgx_target_info_t might be defined */

#include <sgx_ql_quote.h>          // DCAP: QE target info / quote APIs
#include <sgx_dcap_quoteverify.h>  // (任意) 検証APIを使うなら

#include <sgx_dcap_ql_wrapper.h>   // added YI

#include "Enclave_u.h"

#define ENCLAVE_FILE "./enclave.signed.so"

void ocall_print(const char* s) {
    puts(s);
}

int
main(int argc, char** argv)
{
    const char* enclave_path = (argc >= 2) ? argv[1] : ENCLAVE_FILE;

    sgx_enclave_id_t eid = 0;
    sgx_status_t st = SGX_SUCCESS;
    sgx_status_t est = SGX_SUCCESS;
    sgx_launch_token_t tok = {0};
    int updated = 0;

    // 1) Load enclave
    st = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &tok, &updated, &eid, NULL);
    if (st != SGX_SUCCESS) {
        printf("sgx_create_enclave failed: 0x%x\n", st);
        return 1;
    }
    printf("Step %d enclave_path=%s\n", __LINE__, enclave_path);

    // 2) Get QE TargetInfo (DCAP)
    sgx_target_info_t qe_ti = {0};
    quote3_error_t q3e = sgx_qe_get_target_info(&qe_ti);
    if (q3e != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_target_info failed: 0x%x\n", q3e);
        goto out;
    }
    printf("Step %d\n", __LINE__);

    // 3) Ask enclave to create report for QE, embedding custom report_data (64B)
    uint8_t report_data[64] = {0};
    const char* msg = "hello-from-enclave";
    memcpy(report_data, msg, strlen(msg));

    sgx_report_t report = {0};
    st = e_make_report_and_get(eid, &est, &qe_ti, report_data, &report);
    if (st != SGX_SUCCESS) {
        printf("e_make_report_and_get failed: 0x%x\n", st);
        goto out;
    }
    if (est != SGX_SUCCESS) {
	printf("e_make_report_and_get failed inside enclave: 0x%x\n", est);
    }
    printf("Step %d\n", __LINE__);
    puts("Report created by enclave for QE.");

    // 4) Get quote size, then get quote
    uint32_t quote_size = 0;
    q3e = sgx_qe_get_quote_size(&quote_size);
    if (q3e != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_quote_size failed: 0x%x\n", q3e);
        goto out;
    }

    printf("quote_size = %d\n", quote_size);
    uint8_t* quote_buf = (uint8_t*)malloc(quote_size);
    if (!quote_buf) {
        puts("malloc failed");
        goto out;
    }
    q3e = sgx_qe_get_quote(&report, quote_size, quote_buf);
    if (q3e != SGX_QL_SUCCESS) {
        printf("sgx_qe_get_quote failed: 0x%x\n", q3e);
        free(quote_buf);
        goto out;
    }

    printf("Quote generated. size=%u bytes\n", quote_size);
    FILE* f = fopen("quote.bin", "wb");
    if (f) {
        fwrite(quote_buf, 1, quote_size, f);
        fclose(f);
        puts("Saved quote.bin");
    }
    free(quote_buf);

    // 5) (Optional) verify quote locally with QvE-less:
    // uint32_t supplemental_size = 0;
    // sgx_qv_get_quote_supplemental_data_size(&supplemental_size);
    // uint8_t *supplemental = (uint8_t*)malloc(supplemental_size);
    // time_t now = time(NULL);
    // sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    // quote3_error_t vret = sgx_qv_verify_quote(quote_buf, quote_size, NULL,
    //     now, NULL, &qv_result, NULL, supplemental_size, supplemental);
    // printf("qv_result=%d vret=0x%x\n", qv_result, vret);
    // free(supplemental);

out:
    sgx_destroy_enclave(eid);
    return 0;
}
