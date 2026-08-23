#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "Enclave_u.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <cbor.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include "ptlsra.h"
#include "../../tpm2/libquote.h"

int
myssl_printerr(const char *str, size_t len, void *u)
{
    char	*buf = NULL;
    TLSRA_LIBCALLPmsg(err, buf, malloc(len + 1),
		      "%s: Cannot allocate memory size(%ld)\n", __func__, len+1);
    strncpy(buf, str, len);
    buf[len] = 0;
    printf("SSLerror: %s\n", str);
    free(buf);
    return 1;
err:
    printf("%s: cannot allocate memory\n", __func__);
    return 1;
}

static int
hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest,
                   uint8_t *new_hash)
{
    EVP_MD_CTX	*ctx;
    int	len = 0;
    int rc = -1;

    TLSRA_SSLCALLP(err0, ctx, EVP_MD_CTX_new());
    TLSRA_SSLCALL(err1, rc, EVP_DigestInit_ex(ctx, EVP_sha256(), NULL));
    /* Hash(old_hash || digest) */
    TLSRA_SSLCALL(err1, rc, EVP_DigestUpdate(ctx, old_hash, SHA256_DIGEST_LENGTH));
    TLSRA_SSLCALLP(err1, rc, EVP_DigestUpdate(ctx, digest, SHA256_DIGEST_LENGTH));
    TLSRA_SSLCALL(err1, rc, EVP_DigestFinal_ex(ctx, new_hash, &len));
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


/*
 * return value is true (1) or false(0)
 */
static int
add_cbor_map(cbor_item_t *map, const char *key, const uint8_t *val, size_t sz)
{
    cbor_item_t	*ckey;
    cbor_item_t	*cval;
    struct cbor_pair	mapent;
    int	rc = 0; /* false */

    TLSRA_CBORCALLP(err0, ckey, cbor_build_string(key));
    TLSRA_CBORCALLP(err1, cval, cbor_build_bytestring(val, sz));
    mapent.key = ckey;
    mapent.value = cval;
    /* return value is boolean */
    TLSRA_CBORCALL(err2, rc, cbor_map_add(map, mapent));
    rc = 1; /* true */
err2:
    cbor_decref(&cval);
err1:
    cbor_decref(&ckey);
err0:
    return rc;
}

void
ocall_make_tpm2_quote_via_daemon(uint8_t *nonce, int nsize, size_t qbsize,
				 uint8_t *tpm2_serial, size_t *sz)
{
    uint8_t	*tpm2_qbuf = NULL;
    size_t	tpm2_qbsz = 0;
    uint8_t	apphash[32];
    uint8_t	newhash[32];
    int	usize = 32;
    int	alg = TPM2_ALG_SHA256;
    uint8_t	pcrs[] = {0, 1, 2, 7, 10};
    int	count = 5;
    int	rc;
    struct tpm2_quote	t_quote;
    cbor_item_t		*c_tpm2_quote = NULL;
    memset(apphash, 0, usize);

    fprintf(stderr, "HOST:%s: enter tpm2_serial=%p qbsize = %ld\n", __func__, tpm2_serial, qbsize);
    /* app-hash || nonce */
    rc = hash_extend_sha256(apphash, nonce, newhash);
    rc = make_tpm2_quote(newhash, nsize,
			 TPM2_ALG_SHA256, pcrs, count, 0x81018001,
			 &t_quote);
    if (rc < 0) {
	fprintf(stderr, "%s: make_tpm2_quote error\n", __func__);
	goto err0;
    }
    TLSRA_CBORCALLP(err1, c_tpm2_quote, cbor_new_definite_map(3));
    /* cbor-map: quote */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "quote",
				t_quote.quote, t_quote.qsize));
    /* cbor-map: sign */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "sign",
				t_quote.sign, t_quote.ssize));
    /* app-hash */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "app-hash", apphash, usize));
    cbor_serialize_alloc(c_tpm2_quote, &tpm2_qbuf, &tpm2_qbsz);
    if (tpm2_qbsz <= 0 || tpm2_qbsz > *sz) {
	fprintf(stderr, "%s: Cannot serialized at host code\n", __func__);
	fprintf(stderr, "%s: tpm2_quote buffer size must be >= %ld\n", __func__, tpm2_qbsz);
	goto err2;
    }
    fprintf(stderr, "HOST:%s: tpm2_serial=%p tpm2_qbuf=%p tpm2_qbsz=%ld LINE=%d\n", __func__, tpm2_serial, tpm2_qbuf, tpm2_qbsz, __LINE__);
    memcpy(tpm2_serial, tpm2_qbuf, tpm2_qbsz);
    fprintf(stderr, "HOST:%s: LINE=%d\n", __func__, __LINE__);
    /* free */
    free(tpm2_qbuf);
    fprintf(stderr, "HOST:%s: LINE=%d\n", __func__, __LINE__);
err2:
    cbor_decref(&c_tpm2_quote);
    fprintf(stderr, "HOST:%s: LINE=%d\n", __func__, __LINE__);
err1:
    /* t_quote must be free ?? */
err0:
    *sz = tpm2_qbsz;
    fprintf(stderr, "HOST:%s: LINE=%d\n", __func__, __LINE__);
}
