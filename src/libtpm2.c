#include <cbor.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#if SGX_ENCLAVE || SGX_ENCLAVE_WITH_TPM2
/* SGX */
#include "sgxenv.h"
#include <Enclave_t.h>
#endif

#include "ptlsra.h"
#include "libcert.h"

int
hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest,
                   uint8_t *new_hash)
{
    EVP_MD_CTX	*ctx = NULL;
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
    cbor_item_t	*ckey = NULL;
    cbor_item_t	*cval = NULL;
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

static
int
pem2der_sha256(const uint8_t *pem, int pemsz, cbor_item_t **sha256)
{
    BIO		*bio = NULL;
    EVP_PKEY	*pkey = NULL;
    unsigned char	*der = NULL;
    uint8_t	pksha[SHA256_DIGEST_LENGTH];
    cbor_item_t *citem = NULL;
    size_t	len = 0;
    int		rc = -1;

    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    TLSRA_SSLCALLP(err0, bio, BIO_new_mem_buf(pem, pemsz));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    TLSRA_SSLCALLP(err1, pkey, PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    TLSRA_SSLCALLN0(err2, len, i2d_PUBKEY(pkey, &der));
    fprintf(stderr, "%s: LINE=%d PUBKEY len=%ld\n", __func__, __LINE__, len);
    dump("pem2der_sha256: YI!!! pem:", pem, pemsz);
    dump("pem2der_sha256: YI!!! i2d_PUBKEY(der):", der, len);
    SHA256(der, len, pksha);
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    TLSRA_CBORCALLP(err3, citem, cbor_build_bytestring(pksha, SHA256_DIGEST_LENGTH));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    *sha256 = citem;
    rc = 0;
err3:    
    OPENSSL_free(der);
err2:
    EVP_PKEY_free(pkey);
err1:    
    BIO_free(bio);
err0:
    return rc;
}

/*
 * public-key is represented by two entry array:
 *	IANA_HASH_ALG_REGISTRY_SHA256
 *	SHA256(PEMDER(pubkey))
 * The return value is a serialized CBOR map, not a CBOR structure.
 * It must be freed with free(3) after use.
 */
/*
 * return value is true (1) or false(0)
 */
static int
make_cbor_pkhash_entry(const uint8_t *pubkey, size_t pksz,
		       uint8_t **hash, size_t *hsz)
{
    cbor_item_t		*chash_ent = NULL;
    cbor_item_t		*chash_algid = NULL;
    cbor_item_t		*chash_val = NULL;
    int		bval;
    size_t	sz;
    int	rc = 0; /* false */

    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    TLSRA_CBORCALLP(err0, chash_ent, cbor_new_definite_array(2));
    TLSRA_CBORCALLP(err1, chash_algid,
		    cbor_build_uint8(IANA_HASH_ALG_REGISTRY_SHA256));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    /* pubkey: pem --> der --> sha256 */
    dump("Enclave: YI!!! pubkey(pem):", pubkey, pksz);
    TLSRA_LIBCALL(err2, sz, pem2der_sha256(pubkey, pksz, &chash_val));
    dump("Enclave: YI!!! make_cbor_pkhash_entry:",
	 cbor_bytestring_handle(chash_val), cbor_bytestring_length(chash_val));
    /**/
    TLSRA_CBORCALL(err3, bval, cbor_array_push(chash_ent, chash_algid));
    TLSRA_CBORCALL(err3, bval, cbor_array_push(chash_ent, chash_val));
    *hsz = 0;
    TLSRA_CBORCALL_SALLOC(err3, *hsz,
			  cbor_serialize_alloc(chash_ent, hash, hsz));
    fprintf(stderr, "%s: hsz = %ld LINE=%d\n", __func__, *hsz, __LINE__);
    /* success */
    rc = 1; /* success */
err3:
    fprintf(stderr, "%s: chash_algid=%p LINE=%d\n", __func__, chash_algid, __LINE__);
    cbor_decref(&chash_val);
err2:
    fprintf(stderr, "%s: chash_algid=%p LINE=%d\n", __func__, chash_algid, __LINE__);
    cbor_decref(&chash_algid);
err1:
    fprintf(stderr, "%s: chash_ent=%p LINE=%d\n", __func__, chash_ent, __LINE__);
    cbor_decref(&chash_ent);
err0:
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);
    return rc;
}

/*
 * Claims for enclave contain two map entries:
 *	"pubkey-hash"
 *	"nonce":
 * The return value is a serialized CBOR map, not a CBOR structure.
 * It must be freed with free(3) after use.
 */
#define MAX_TMP2QUOTE_SERIALIZE	1024
int
make_cbor_tpm2_claims_from_enclave(uint8_t *pubkey, int pubksz,
				   uint8_t *nonce, int nsize,
				   uint8_t **claims, size_t *csz)
{
    cbor_item_t		*c_claims = NULL;
    uint8_t	*chash_val = NULL;
    size_t	chash_sz = 0;
    uint8_t	*claims_buf = NULL;
    size_t	claims_bufsz;
    uint8_t	tpm2_qbuf[MAX_TMP2QUOTE_SERIALIZE];
    size_t	tpm2_qbsz;
    int	cret;
    int	rc = -1;

    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);
    TLSRA_CBORCALLP(err0, c_claims, cbor_new_definite_map(3));
    fprintf(stderr, "%s: YI!!! cbor_new_definite_map(3) LINE=%d\n", __func__, __LINE__);    
    /*
     * 1st entry: "cbor pubkey-hash"
     */
    /* chash_val must be free */
    TLSRA_CBORCALL(err1, rc,
		   make_cbor_pkhash_entry(pubkey, pubksz, &chash_val, &chash_sz));
    fprintf(stderr, "%s: chash_sz = %ld LINE=%d\n", __func__, chash_sz, __LINE__);
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_claims, "pubkey-hash", chash_val, chash_sz));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    /*
     * 2nd entry: "nonce"
     */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_claims, "nonce", nonce, nsize));
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);    
    /*
     * 3rd entry: "tpm2quot"
     */
    fprintf(stderr, "%s: OCALL tpm2_qbuf=%p tpm2_qbsz=%ld LINE=%d\n", __func__, tpm2_qbuf, tpm2_qbsz, __LINE__);
    ocall_make_tpm2_quote_via_daemon(nonce, nsize, sizeof(tpm2_qbuf), tpm2_qbuf, &tpm2_qbsz);
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);
    if (tpm2_qbsz <= 0) {
	goto err2;
    }
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_claims, "tpm2-quote", tpm2_qbuf, tpm2_qbsz));
    /*
     * claims are serialized, byte-stream
     */
    TLSRA_CBORCALL_SALLOC(err2, claims_bufsz,
			  cbor_serialize_alloc(c_claims, &claims_buf, &claims_bufsz));
    /* success */
    fprintf(stderr, "%s: YI!!! claims SUCESS LINE=%d\n", __func__, __LINE__);
    *claims = claims_buf;
    *csz = claims_bufsz;
    rc = 0;
err2:
    free(chash_val);
err1:
    cbor_decref(&c_claims);
err0:
    return rc;
}


/*
 * Claims contain two map entries:
 *	"pubkey-hash"
 *	"nonce":
 * The return value is a serialized CBOR map, not a CBOR structure.
 * It must be freed with free(3) after use.
 */
int
make_cbor_tpm2_claims(uint8_t *pubkey, int pubksz,
		      uint8_t *nonce, int nsize,
		      uint8_t **claims, size_t *csz)
{
    cbor_item_t		*c_claims = NULL;
    uint8_t	*chash_val = NULL;
    size_t	chash_sz;
    uint8_t	*claims_buf = NULL;
    size_t	claims_bufsz;
    int	cret;
    int	rc = -1;

    TLSRA_CBORCALLP(err0, c_claims, cbor_new_definite_map(2));
    /*
     * 1st entry: "pubkey-hash"
     */
    TLSRA_CBORCALL(err1, rc,
		   make_cbor_pkhash_entry(pubkey, pubksz, &chash_val, &chash_sz));
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_claims, "pubkey-hash", chash_val, chash_sz));
    /*
     * 2nd entry: "nonce"
     */
    TLSRA_CBORCALL(err2, rc, add_cbor_map(c_claims, "nonce", nonce, nsize));
    /* claims are serialized, byte-stream */
    TLSRA_CBORCALL_SALLOC(err2, claims_bufsz,
			  cbor_serialize_alloc(c_claims, &claims_buf, &claims_bufsz));
    /* success */
    *claims = claims_buf;
    *csz = claims_bufsz;
    rc = 0;
err2:
    free(chash_val);
err1:
    cbor_decref(&c_claims);
err0:
    return rc;
}

/*
 * make_cbor_tri_tpm2_evidence: 
 *	tagged evidence (IANA_CBOR_TAG_TRINITY_TPM2_QUOTE) contains cbor quote
 */
int
make_cbor_tri_tpm2_evidence(uint8_t *quote, size_t quotesz,
			    uint8_t *claim, size_t claimsz,
			    uint8_t **out_evidence, size_t *evidence_size)
{
    cbor_item_t	*evidence = NULL;
    cbor_item_t	*tagged_evidence = NULL;
    uint8_t	*ebuf;
    size_t	ebufsz;
    int	rc;

    *out_evidence = NULL; *evidence_size = 0;
    TLSRA_CBORCALLP(err0, evidence, cbor_new_definite_array(2));
    { /* cbor_evidence: quote bytestring */
	cbor_item_t	*cbor_quote = NULL;
	TLSRA_CBORCALLP(err1, cbor_quote,
			cbor_build_bytestring(quote, quotesz));
	/* result value is boolean */
	TLSRA_CBORCALL(err2, rc, cbor_array_push(evidence, cbor_quote));
	goto ok;
    err2:
	cbor_decref(&cbor_quote);
    err1:
	cbor_decref(&evidence);
	return -1;
    ok:
	cbor_decref(&cbor_quote);
    }
    /**/
    TLSRA_CBORCALLP(err3, tagged_evidence,
		    cbor_new_tag(IANA_CBOR_TAG_TRINITY_TPM2_QUOTE));
    cbor_tag_set_item(tagged_evidence, evidence);

    /* tagged evidence is serialized */
    TLSRA_CBORCALL_SALLOC(err4, ebufsz,
			  cbor_serialize_alloc(tagged_evidence, &ebuf, &ebufsz));
    cbor_decref(&evidence);
    cbor_decref(&tagged_evidence);
    *out_evidence = ebuf;
    *evidence_size = ebufsz;
    return 0;
err4:
    *out_evidence = 0;
    *evidence_size = 0;
    cbor_decref(&evidence);
err3:
    cbor_decref(&tagged_evidence);
    cbor_decref(&evidence);
err0:
    return -1;
}
