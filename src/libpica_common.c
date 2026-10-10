/*
 * Common Library for PICA
 *    This module may be linked with both host and tee sides:
 *
 */
#include "libpica_common.h"
#include "error_check.h"
#include "libio.h"
#include <openssl/bio.h>
#include <openssl/err.h>

void
hexdump(FILE *fp, const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(fp, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(fp, "%02x:", bf[i]);
    }
    fprintf(fp, "\n");
}

float
time_to_msec(int64_t st_sec, int64_t st_nsec, int64_t et_sec, int64_t et_nsec)
{
    int64_t sec = et_sec - st_sec;
    int64_t nsec = et_nsec - st_nsec;
    double msec;
    msec = (((double)sec*1000) + (double)(nsec)/(double)1000000);
    return (float) msec;
}

int
hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest, uint8_t *new_hash)
{
    EVP_MD_CTX	*ctx;
    uint32_t	len = 0;
    int rc = -1;

    SSL_CALLP(err0, ctx, EVP_MD_CTX_new());
    SSL_CALL(err1, rc, EVP_DigestInit_ex(ctx, EVP_sha256(), NULL));
    /* Hash(old_hash || digest) */
    SSL_CALL(err1, rc, EVP_DigestUpdate(ctx, old_hash, SHA256_DIGEST_LENGTH));
    SSL_CALLP(err1, rc, EVP_DigestUpdate(ctx, digest, SHA256_DIGEST_LENGTH));
    SSL_CALL(err1, rc, EVP_DigestFinal_ex(ctx, new_hash, &len));
    if (len == SHA256_DIGEST_LENGTH) {
	rc = 0;
    } else {
	fprintf(stderr, "%s: size is not %d(SHA256_DIGEST_LENGTH)\n", __func__, SHA256_DIGEST_LENGTH);
    }
err1:
    EVP_MD_CTX_free(ctx);
err0:
    return rc;
}

int
comp_pcr_selection(const TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b)
{
    int	i;
    VERBOSE(VERB_ALL) fprintf(stderr, "%s: count(%d) count(%d)\n", __func__, a->count, b->count);
    if (a->count != b->count)  return -1;
    for (i = 0; i < a->count; i++) {
        const TPMS_PCR_SELECTION *sa = &a->pcrSelections[i];
        const TPMS_PCR_SELECTION *sb = &b->pcrSelections[i];
        if (sa->hash != sb->hash)  return -1;
        if (sa->sizeofSelect != sb->sizeofSelect) return -1;
        if (memcmp(sa->pcrSelect, sb->pcrSelect, sa->sizeofSelect) != 0) return -1;
    }
    return 0;
}

void
show_tpm2quote_info(const char *msg, TPMS_QUOTE_INFO *qinfo)
{
    TPML_PCR_SELECTION	*pcrSelect = &qinfo->pcrSelect;
    TPM2B_DIGEST	*pcrDigest = &qinfo->pcrDigest;
    int	i;

    fprintf(stderr, "*********** TPM2 Quote (%s) ************\n", msg);
    fprintf(stderr, "\tTPML_PCR_SECELCTION: count(%d)\n", pcrSelect->count);
    for (i = 0; i < pcrSelect->count; i++) {
	TPMS_PCR_SELECTION	*sel = &pcrSelect->pcrSelections[i];
	fprintf(stderr, "\thash = 0x%04x\n", sel->hash);
	fprintf(stderr, "\tsizeofSelect = %u\n", sel->sizeofSelect);
	fprintf(stderr, "\tSelected PCRs:");
	for (UINT32 pcr = 0;  pcr < sel->sizeofSelect * 8;  pcr++) {
	    if (sel->pcrSelect[pcr / 8] & (1 << (pcr % 8))) {
		fprintf(stderr, " %u", pcr);
	    }
	}
	fprintf(stderr, "\n");
    }
    fprintf(stderr, "\tDigest(size = %d): ", pcrDigest->size);
    for (i = 0; i < pcrDigest->size; i++) {
	fprintf(stderr, "%02x:", pcrDigest->buffer[i]);
    }
    fprintf(stderr, "\n");
}

void
show_procinfo(struct procinfo *cpif, int proc_cnt)
{
    int	i;
    for (i = 0; i < proc_cnt; i++) {
	int	j;
	struct fdigest	*fdigp = cpif[i].libs;

	printf("[%d]\tpath: %s\n", i, cpif[i].path);
	printf("\truid: %d\n", cpif[i].ruid);
	hexdump(stdout, "\tdigest: ", cpif[i].digest, 32);
	printf("\tlibs: %d\n", cpif[i].count);

	for (j = 0; j < cpif[i].count; j++) {
	    printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
	    hexdump(stdout, "\t\t->digest: ", fdigp[j].digest, 32);
	}
    }
}

/*
 * Procinfo table is freed
 */
void
free_pinfo(struct procinfo *pinfo, int entries)
{
    int	i, j;
    //printf("%s: pinfo[0].path = %p\n", __func__, pinfo[0].path);
    for (i = 0; i < entries; i++) {
	if (pinfo[i].path) free(pinfo[i].path);
	for (j = 0; j < pinfo[i].count; j++) {
	    // printf("pinfo[%d].libs[%d].path = %p\n", i, j, pinfo[i].libs[j].path);
	    free(pinfo[i].libs[j].path);
	}
	free (pinfo[i].libs);
    }
    free(pinfo);
}
