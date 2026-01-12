#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include "Enclave_t.h"

sgx_status_t e_make_report_and_get(sgx_target_info_t* qe_ti,
                                   uint8_t *report_data,
                                   sgx_report_t* out_report)
{
    if (!qe_ti || !out_report) return SGX_ERROR_INVALID_PARAMETER;

    sgx_report_data_t rd = {0};

    ocall_print("Enclave called");
    memcpy(rd.d, report_data, sizeof(rd.d));  // 任意の64Bを埋め込める

    sgx_report_t report = {0};
    sgx_status_t st = sgx_create_report(qe_ti, &rd, &report);
    if (st != SGX_SUCCESS) {
        ocall_print("sgx_create_report failed");
        return st;
    }
    *out_report = report;  // 構造体コピーで返す
    return SGX_SUCCESS;
}
