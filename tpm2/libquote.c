#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "libquote.h"

extern int	vflag;
#define VERBOSE	if (vflag)

#define TPM2_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != TSS2_RC_SUCCESS) {	\
	tss_error(#command, rc);	\
        goto lbl;			\
    }					\
} while(0)


#define CRYPT_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	fprintf(stderr, "%s: error %s\n", __func__, #command);	\
        goto lbl;			\
    }					\
} while(0)

#define SSL_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != 1) {			\
        ERR_print_errors_fp(stderr);	\
        goto lbl;			\
    }					\
} while(0)

#define SSL_CALLP(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	ERR_print_errors_fp(stderr);	\
        goto lbl;			\
    }					\
} while(0)


static void
dump(const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(stderr, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(stderr, "%02x:", bf[i]);
    }
    fprintf(stderr, "\n");
}

static void
tss_error(const char *cmd, TSS2_RC rc)
{
    const char	*message = Tss2_RC_Decode(rc);
    fprintf(stderr, "%s failed: 0x%x (%s)\n",  cmd, rc,
	    (message == NULL) ? "unknown TSS2 error" : message);
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

int
hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest,
                   uint8_t *new_hash)
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

int
make_sig_scheme(ESYS_CONTEXT *esys_context,
		ESYS_TR signing_key,
		TPMT_SIG_SCHEME *scheme)
{
    TPM2B_PUBLIC		*public = NULL;
    const TPMT_ASYM_SCHEME	*key_scheme = NULL;
    TPMI_ALG_PUBLIC		key_type;
    TPMI_ALG_HASH		key_hash;
    TSS2_RC	rc;
    int		err = -1;

    TPM2_CALL(err, rc, Esys_ReadPublic(esys_context, signing_key,
				       ESYS_TR_NONE, ESYS_TR_NONE,
				       ESYS_TR_NONE, &public, NULL, NULL));
    if ((public->publicArea.objectAttributes &
         TPMA_OBJECT_SIGN_ENCRYPT) == 0) {
        fprintf(stderr, "TPM handle is not a signing key\n");
        goto out;
    }

    key_type = public->publicArea.type;
    key_scheme = &public->publicArea.parameters.asymDetail.scheme;
    key_hash = key_scheme->details.anySig.hashAlg;

    memset(scheme, 0, sizeof(*scheme));

    if (key_scheme->scheme != TPM2_ALG_NULL &&
        key_hash != TPM2_ALG_NULL &&
        key_hash != TPM2_ALG_SHA256) {
        fprintf(stderr, "The key is restricted to hash algorithm 0x%04x, "
                "not SHA-256\n", key_hash);
        goto out;
    }

    switch (key_type) {
    case TPM2_ALG_RSA:
        if (key_scheme->scheme == TPM2_ALG_NULL) {
            scheme->scheme = TPM2_ALG_RSASSA;
	} else if (key_scheme->scheme == TPM2_ALG_RSASSA ||
		   key_scheme->scheme == TPM2_ALG_RSAPSS) {
            scheme->scheme = key_scheme->scheme;
	} else {
            fprintf(stderr, "Unsupported RSA signing scheme: 0x%04x\n",
                    key_scheme->scheme);
            goto out;
        }
        break;
    case TPM2_ALG_ECC:
        if (key_scheme->scheme == TPM2_ALG_NULL) {
            scheme->scheme = TPM2_ALG_ECDSA;
	} else if (key_scheme->scheme == TPM2_ALG_ECDSA) {
            scheme->scheme = key_scheme->scheme;
	} else {
            fprintf(stderr, "Unsupported ECC signing scheme: 0x%04x\n",
                    key_scheme->scheme);
            goto out;
        }
        break;
    default:
        fprintf(stderr, "Unsupported signing-key type: 0x%04x\n",
                key_type);
        goto out;
    }
    err = 0;
    scheme->details.any.hashAlg = TPM2_ALG_SHA256;
out:
    Esys_Free(public);
err:
    return err;
}

/*
 *	int pcrs[] = { 0, 1, 2, 7, 10 };
 *	pcr_select(sel, TPM2_ALG_SHA256, pcrs, 5);
 */
static void
pcr_select(TPML_PCR_SELECTION *sel, int alg, uint8_t *pcrs, int count)
{
    int		i;
    uint8_t	pcr;

    memset(sel, 0, sizeof(TPML_PCR_SELECTION));

    sel->count = 1;
    sel->pcrSelections[0].hash = alg;
    sel->pcrSelections[0].sizeofSelect = 3; /* 24 registers */

    for (i = 0; i < count; i++) {
        pcr = pcrs[i];
        sel->pcrSelections[0].pcrSelect[pcr / 8] |= (BYTE) (1u << (pcr % 8));
    }
    VERBOSE {
	fprintf(stderr, "%s: ", __func__);
	for (i = 0; i < 32/8; i++) {
	    fprintf(stderr, "%02x:", sel->pcrSelections[0].pcrSelect[i]);
	}
	fprintf(stderr, "\n");
    }
}

/*
 * make_tpm2_quote(uint8_t *udata, int usize,
 *		   int alg, uint8_t *pcrs, int count, uint32_t handle,
 *		   trinity_quote *quote)
 *   e.g.,
 *		alg:    TPM2_ALG_SHA256
 *		pcrs:   pcrs[] = {0, 1, 2, 7, 10}
 *		count:  5
 *		handle: 0x81018001
 *			 TPM2_HANDLE: uint32_t
 *			 denotes attestation key object
 *		
 * TSS2_RC code is not propagated to the caller.
 */
int
make_tpm2_quote(uint8_t *udata, int usize,
		int alg, uint8_t *pcrs, int count, uint32_t handle,
		struct tpm2_quote *t_quote)
{
    TSS2_TCTI_CONTEXT	*tctx = NULL;
    ESYS_CONTEXT	*ectx = NULL;
    TPM2B_ATTEST	*quoted;
    TPMT_SIGNATURE	*sig;
    ESYS_TR		skey = ESYS_TR_NONE;
    TPMT_SIG_SCHEME	sig_scheme;
    TPML_PCR_SELECTION	pcr_sel;
    TPM2B_AUTH		empty_auth;
    TPM2B_DATA		qdata;
    size_t		off = 0;
    TSS2_RC		rc;
    int			err = -1;

    if (t_quote == NULL) {
	return err;
    }
    qdata.size = usize;
    memcpy(qdata.buffer, udata, usize);
    VERBOSE {
	dump("@@@@@@@@@@@@@@@@@@ TPM qdata: ", qdata.buffer, usize);
    }
    /* Initializing TSS2 context */
    TPM2_CALL(ext, rc, Tss2_TctiLdr_Initialize(NULL, &tctx));
    /* Initializing ESYS context */
    TPM2_CALL(ext, rc, Esys_Initialize(&ectx, tctx, NULL));
    /* Obtaining Sign Key (AK key) */
    TPM2_CALL(ext, rc,
	      Esys_TR_FromTPMPublic(ectx, handle,
				    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				    &skey));
    /* Setup authorization (null) */
    memset(&empty_auth, 0, sizeof(empty_auth));
    rc = Esys_TR_SetAuth(ectx, skey, &empty_auth);
    /* Signature Scheme */
    if ((err = make_sig_scheme(ectx, skey, &sig_scheme)) < 0) {
	/* error */
	goto ext;
    }
    /* Selecting PCR registers */
    pcr_select(&pcr_sel, alg, pcrs, count);
    /*
     * Esys_Quote:
     *    quoted: TPM2B_ATTEST
     *			{ uint16 size; uint8_t attdata[sizeof(TPMS_ATTEST)]; }
     *    sig: TPMT_SIGNATURE consists of
     *		TPMI_ALG_SIG_SCHEME sigAlg
     *		TPMU_SIGNATURE signature (union)
     *			RSASSA, RSAPSS, ECDSA, ECDAA, SM2, ECSCHNORR, HMAC, ...
     * See /usr/include/tss2/tss2_tpm2_types.h
     */
    TPM2_CALL(ext, rc, Esys_Quote(ectx, skey,
				  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				  &qdata, &sig_scheme, &pcr_sel,
				  &quoted, &sig));
    if (quoted->size > MAX_QUOTESIZE) {
	fprintf(stderr, "Internal error: quoted.size(%d) > %d\n",
		quoted->size, MAX_QUOTESIZE);
	goto err_ext;
    }
    /* setup trinity_quote structure (out) */
    t_quote->qtype = QUOTE_TPM2;
    t_quote->qsize = quoted->size;
    /* copy quote */
    memcpy(t_quote->quote, quoted->attestationData, quoted->size);
    /* marshaling signature */
    TPM2_CALL(err_ext, rc, Tss2_MU_TPMT_SIGNATURE_Marshal(
		  sig, t_quote->sign, SIGNSIZE, &off));
    t_quote->ssize = off;
    //printf("qsize = %d, ssize = %d, off = %ld\n",t_quote->qsize, t_quote->ssize, off);
err_ext:
    Esys_Free(quoted);
    Esys_Free(sig);
ext:
    return err;
}

int
unmarshal_sign(uint8_t *marshal_sign, size_t size, TPMT_SIGNATURE *sig)
{
    size_t	off = 0;
    int	rc = -1;

    if (sig == NULL) {
	fprintf(stderr, "%s: sig is NULL\n", __func__);
	return rc;
    }
    TPM2_CALL(err, rc,
	      Tss2_MU_TPMT_SIGNATURE_Unmarshal(marshal_sign, size, &off, sig));
    rc = 0;
err:
    return rc;
}


static int
tpm_ecdsa_to_der(const TPMS_SIGNATURE_ECDSA *tpm_sig,
                 unsigned char *der,  int *der_len)
{
    ECDSA_SIG	*sig = NULL;
    BIGNUM	*r = NULL;
    BIGNUM	*s = NULL;
    unsigned char *tmp;
    int	trc, rc = -1;
    int	len;

    CRYPT_CALL(err, r,
	       BN_bin2bn(tpm_sig->signatureR.buffer, tpm_sig->signatureR.size, NULL));
    CRYPT_CALL(err, s,
	       BN_bin2bn(tpm_sig->signatureS.buffer, tpm_sig->signatureS.size, NULL));
    CRYPT_CALL(err, sig, ECDSA_SIG_new());
    SSL_CALL(err, trc, ECDSA_SIG_set0(sig, r, s));
    /* query required size */
    len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        goto err;
    }
    if (len > *der_len) {
	fprintf(stderr, "%s: ecdsa_der requires %d byte, but %d\n", __func__, len, *der_len);
	goto err;
    }
    tmp = der;
    if (i2d_ECDSA_SIG(sig, &tmp) != len) {
        goto err;
    }
    *der_len = len;
    rc = 0;
err:
    if (r) BN_free(r);
    if (s) BN_free(s);
    if (sig) ECDSA_SIG_free(sig);
    return rc;
}

/*
 * verify_tpm2_quote returns
 *	0 : Verify Success
 *	-1: Verify Failed
 */
int
verify_tpm2_quote(const uint8_t *s_quoted, int sq_size,
		  const TPMT_SIGNATURE *sig, EVP_PKEY *ak_pubkey)
{
    TPMI_ALG_HASH	hash_alg;
    const EVP_MD	*md;
    EVP_MD_CTX		*mdctx = NULL;
    EVP_PKEY_CTX	*pkey_ctx = NULL;
    const unsigned char *sig_data = NULL;
    size_t sig_size = 0;
    unsigned char	ecdsa_der[1024];
    int			ecdsa_der_size = sizeof(ecdsa_der);
    TSS2_RC trc;
    int ret, rc = -1;

    switch (sig->sigAlg) {
    case TPM2_ALG_RSASSA:
        hash_alg = sig->signature.rsassa.hash;
        sig_data = sig->signature.rsassa.sig.buffer;
        sig_size = sig->signature.rsassa.sig.size;
        break;
    case TPM2_ALG_RSAPSS:
        hash_alg = sig->signature.rsapss.hash;
        sig_data = sig->signature.rsapss.sig.buffer;
        sig_size = sig->signature.rsapss.sig.size;
        break;
    case TPM2_ALG_ECDSA:
        hash_alg = sig->signature.ecdsa.hash;
        if (tpm_ecdsa_to_der(&sig->signature.ecdsa, ecdsa_der,
			     &ecdsa_der_size) != 0) {
            fprintf(stderr, "ECDSA signature conversion failed\n");
            return -1;
        }
        sig_data = ecdsa_der;
        sig_size = ecdsa_der_size;
        break;
    default:
        fprintf(stderr, "%s: Unsupported signature algorithm: 0x%04x\n",
		__func__, sig->sigAlg);
        return -1;
    }
    switch (hash_alg) {
    case TPM2_ALG_SHA1:   md = EVP_sha1(); break;
    case TPM2_ALG_SHA256: md = EVP_sha256(); break;
    case TPM2_ALG_SHA384: md = EVP_sha384(); break;
    case TPM2_ALG_SHA512: md = EVP_sha512();break;
    default:
	fprintf(stderr, "%s: Unsupported hash algorithm: 0x%04x\n",
		__func__, hash_alg);
	goto err;
    }

    SSL_CALLP(err, mdctx, EVP_MD_CTX_new());
    SSL_CALL(err, ret, EVP_DigestVerifyInit(mdctx, &pkey_ctx,
					    md, NULL, ak_pubkey));
    if (sig->sigAlg == TPM2_ALG_RSASSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            ERR_print_errors_fp(stderr);
            goto err;
        }
    } else if (sig->sigAlg == TPM2_ALG_RSAPSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            ERR_print_errors_fp(stderr); goto err;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md) <= 0) {
            ERR_print_errors_fp(stderr); goto err;
        }
    }
    if (EVP_DigestVerifyUpdate(mdctx, s_quoted, sq_size) != 1) {
        ERR_print_errors_fp(stderr); goto err;
    }
    trc = EVP_DigestVerifyFinal(mdctx, sig_data, sig_size);
    if (trc == 1) {
	VERBOSE {
	    fprintf(stderr, "TPM2 Quote signature: VALID\n");
	}
	rc = 0;
    } else if (trc == 0) {
	VERBOSE {
	    fprintf(stderr, "TPM2 Quote signature: INVALID\n");
	}
    } else {
	VERBOSE {
	    fprintf(stderr, "OpenSSL signature verification error\n");
	}
        ERR_print_errors_fp(stderr);
    }
err:
    EVP_MD_CTX_free(mdctx);
    return rc;
}

#ifdef LIBQUOTE_TEST
#define NONCE_SIZE	32
int	vflag = 0;
int
main(int argc, char **argv)
{
    uint8_t	nonce[NONCE_SIZE];
    int		nsize = NONCE_SIZE;
    uint8_t	pcrs[] = {0, 1, 2, 7, 10};
    struct tpm2_quote	t_quote;
    int count = 5;
    int	i;
    int rc;

    printf("sizeof(TPMT_SIGNATURE) = %ld\n", sizeof(TPMT_SIGNATURE));
    for (i = 0; i < NONCE_SIZE; i++) {
	nonce[i] = random();
    }
    rc = make_tpm2_quote(nonce, nsize,
			 TPM2_ALG_SHA256, pcrs, count, 0x81018001,
			 &t_quote);
    if (rc < 0) goto ext;
    printf("rc = 0x%x\n", rc);
    /*
     * Checking marshaled quote and signature
     *		quote: unmarshaling by Tss2_MU_TPMS_ATTEST_Unmarshal()
     *			- offset is the reading position of the buffer
     *			- returned offset is the next position after
     *			  unmarshaling
     *	        signature:
     */
    {
	size_t		off = 0;
	TPMS_ATTEST	tpm_atst;
	TPMT_SIGNATURE	tpm_sig;

	/* unmarashaling quote */
	TPM2_CALL(err_skip, rc,
		  Tss2_MU_TPMS_ATTEST_Unmarshal(t_quote.quote,
						t_quote.qsize, &off,
						&tpm_atst));
	/*
	 * magic ff544347
	 * 0x474354ff
	 */
	printf("magic = 0x%x (%s)\n", tpm_atst.magic,
	       (tpm_atst.magic == TPM2_GENERATED_VALUE) ?
	       "TPM2_GENERATED_VALUE" : "NOT TPM2_GENERATED_VALUE");
	/*
	 * TPM2_ST_ATTEST_QUOTE 0x8018
	 */
	printf("type = 0x%x (%s)\n", tpm_atst.type,
	       (tpm_atst.type == TPM2_ST_ATTEST_QUOTE) ?
	       "QUOTE" : "");

	/* unmarashaling signature */
	off = 0;
	TPM2_CALL(err_skip, rc,
		  Tss2_MU_TPMT_SIGNATURE_Unmarshal(t_quote.sign,
						   t_quote.ssize, &off,
						   &tpm_sig));
    err_skip:
	;
    }
ext:
    return rc;
}
#endif
