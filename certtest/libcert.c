/*
 * Intel SGX EPID
 *	1.2.840.113741.1.13.1 SGX_EXTENSIONS_OID_STR
 *	1.2.840.113741.1.13.1.1 SGX_PPID_OID_STR
 *	1.2.840.113741.1.13.1.2 SGX_TCB_OID_STR
 *	1.2.840.113741.1.13.1.2.17 SGX_PCESVN_OID_STR
 *	1.2.840.113741.1.13.1.2.18 SGX_CPUSVN_OID_STR
 *	1.2.840.113741.1.13.1.3 SGX_PCEID_OID_STR
 *	1.2.840.113741.1.13.1.4 SGX_FMSPC_OID_STR
 *	1.2.840.113741.1.13.1.5 SGX_SGXTYPE_OID_STR
 *	1.2.840.113741.1.13.1.6 SGX_PLATFORM_INSTANCE_ID_OID_STR
 *	1.2.840.113741.1.13.1.7 SGX_CONFIGURATION_OID_STR
 *	1.2.840.113741.1.13.1.7.1 SGX_DYNAMIC_PLATFORM_OID_STR
 *	1.2.840.113741.1.13.1.7.2 SGX_CACHED_KEYS_OID_STR
 *	1.2.840.113741.1.13.1.7.3 SGX_SMT_ENABLED_OID_STR
 *	1.2.840.113741.1.13.1.20 SGX_UNEXPECTED_EXTENSION_OID_STR
 *	
 * Intel SGX DCAP ECDSA
 * 1.2.840.113741.1337.2
 *	840    -- Intel
 *	113741 -- Intel SGX
 *	1337   -- SGX enclave
 *	2      -- Quote
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "libcert.h"
#include <cbor.h>

//#define REPORT_CRITICAL
#ifdef REPORT_CRITICAL
#define REPORT_CRIT	1
#else
#define REPORT_CRIT	0
#endif
#define YEAR_ONE	(60L*60L*24L*365L)

/*
 * attestation evidence data tags,
 * https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
 */
#define TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG 60000
#define IANA_CBOR_TAG_INTEL_TEE_QUOTE	60000
#define IANA_CBOR_TAG_INTEL_TEE_REPORT	60001
#define IANA_CBOR_TAG_INTEL_SGX_REPORT	60002
/*
 *
 */
#define X509_OID_FOR_QUOTE_STRING "1.2.840.113741.1.13.1"
/*
 * TCG DICE(Device Identifier Composition Engine）definition
 *	2.23.133.5.4.9  -- "tagged evidence"
 * https://datatracker.ietf.org/doc/draft-ietf-rats-evidence-trans/00/
 */
#define TCG_DICE_TAGGED_OID_STR "2.23.133.5.4.9"
/*
 * hash IDs per IANA:
 *  https://www.iana.org/assignments/named-information/named-information.xhtml
 */
#define PUB_KEY_MAX_SIZE 626
#define IANA_HASH_ALG_REGISTRY_RESERVED 0
#define IANA_HASH_ALG_REGISTRY_SHA256   1
#define IANA_HASH_ALG_REGISTRY_SHA384   7
#define IANA_HASH_ALG_REGISTRY_SHA512   8
#define RAW_QUOTE_MAX_SIZE 8192
#define CBOR_QUOTE_MAX_SIZE ((RAW_QUOTE_MAX_SIZE)*2)
#define QUOTE_MIN_SIZE 1020


static int
myssl_printerr(const char *str, size_t len, void *u)
{
    printf("SSLerror: %s\n", str);
    return -1;
}

/*
 * generate PKI key pair
 * NID_secp384r1:	NIST P-384
 */
static EVP_PKEY	*
genpkey()
{
    int	rc;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    TLSRA_CALL0(err0, pkey, EVP_PKEY_new());
    TLSRA_CALL0(err1, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    TLSRA_CALL1(err1, rc, EVP_PKEY_keygen_init(ctx));
    TLSRA_CALLP(err1, rc, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1));
     /* Generate key */
    TLSRA_CALL1(err_ret, rc, EVP_PKEY_keygen(ctx, &pkey));
err_ret:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
err1:
    EVP_PKEY_free(pkey);
    pkey = NULL;
err0:
    goto err_ret;
}

EVP_PKEY	*
make_keypair(uint8_t **pbkey, int *pbsz, uint8_t **prkey, int *prsz)
{
    uint8_t	*pubkey = NULL;
    uint8_t	*privkey = NULL;
    int		pubsz = 0;
    int		privsz = 0;
    EVP_PKEY	*pkey = NULL;
    BIO		*bio = NULL;
    int	rc;
    *pbkey = NULL; *pbsz = 0; *prkey = NULL; *prsz = 0;
    TLSRA_CALL0(err0, pkey, genpkey());
    /* Convert PEM format */
    TLSRA_CALL0(err0, bio, BIO_new(BIO_s_mem()));
    /**/
    TLSRA_CALL1(err0, rc, PEM_write_bio_PUBKEY(bio, pkey));
    pubsz = BIO_pending(bio);
    printf("pubsz = %d\n", pubsz);
    TLSRA_LIBCALL0(err0, pubkey, malloc(pubsz + 1));
    memset(pubkey, 0, pubsz + 1);
    rc = BIO_read(bio, pubkey, pubsz);
    if (rc != pubsz) {
	printf("%s: Cannot read %d byte (actual read %d)\n", __func__, pubsz, rc);
    }
    /* */
    TLSRA_CALL1(err0, rc,
		PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL));
    privsz = BIO_pending(bio);
    printf("privsz = %d\n", privsz);
    TLSRA_LIBCALL0(err0, privkey, malloc(privsz + 1));
    memset(privkey, 0, privsz + 1);
    rc = BIO_read(bio, privkey, privsz);
    if (rc != privsz) {
	printf("%s: Cannot read %d byte (actual read %d)\n", __func__, pubsz, rc);
    }
    BIO_free(bio);
    if (pbkey) {
	*pbkey = pubkey;  *pbsz = pubsz;
    } else {
	free(pubkey);
    }
    if (prkey) {
	*prkey = privkey;  *prsz = privsz;
    } else {
	free(privkey);
    }
    return pkey;
err0:
    if (privkey) free(privkey);
    if (pubkey) free(pubkey);
    if (bio) BIO_free(bio);
    if (pkey) EVP_PKEY_free(pkey);
    return NULL;
}

static int
add_ext(X509 *cert, int nid, char *val, X509V3_CTX *ctx)
{
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, ctx, nid, val);
    int	rc;
    rc = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return rc;
}

// support functions
static char b64revtb[256] = {
  -3, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*0-15*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*16-31*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /*32-47*/
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1, /*48-63*/
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /*64-79*/
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /*80-95*/
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /*96-111*/
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /*112-127*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*128-143*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*144-159*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*160-175*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*176-191*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*192-207*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*208-223*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /*224-239*/
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  /*240-255*/
};

static unsigned int
raw_base64_decode(uint8_t *in,
		  uint8_t *out, int strict, int *err)
{
    unsigned int  result = 0;
    int x = 0;
    unsigned char buf[3] = {0, 0, 0};
    unsigned char *p = in, pad = 0;

    *err = 0;
    while (!pad) {
        switch ((x = b64revtb[*p++])) {
            case -3: /* NULL TERMINATOR */
                if (((p - 1) - in) % 4) *err = 1;
                return result;
            case -2: /* PADDING CHARACTER. INVALID HERE */
                if (((p - 1) - in) % 4 < 2) {
                    *err = 1;
                    return result;
                } else if (((p - 1) - in) % 4 == 2) {
                    /* Make sure there's appropriate padding */
                    if (*p != '=') {
                        *err = 1;
                        return result;
                    }
                    buf[2] = 0;
                    pad = 2;
                    result++;
                    break;
                } else {
                    pad = 1;
                    result += 2;
                    break;
                }
                return result;
            case -1:
                if (strict) {
                    *err = 2;
                    return result;
                }
                break;
            default:
                switch (((p - 1) - in) % 4) {
                    case 0:
                        buf[0] = (unsigned char)(x << 2);
                        break;
                    case 1:
                        buf[0] |= (unsigned char)(x >> 4);
                        buf[1] = (unsigned char)(x << 4);
                        break;
                    case 2:
                        buf[1] |= (unsigned char)(x >> 2);
                        buf[2] = (unsigned char)(x << 6);
                        break;
                    case 3:
                        buf[2] |= (unsigned char)x;
                        result += 3;
                        for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
                        break;
                }
                break;
        }
    }
    for (x = 0;  x < 3 - pad;  x++) *out++ = buf[x];
    return result;
}

/*
 * strip header and footer
 */
void
PEM_strip(uint8_t *pem, int pem_len,
	  uint8_t *stripped_pem, int *real_pem_len)
{
    int i = 0;
    int j = 0;
    int real_begin = 0;
    int real_end = 0;
    /* first line is skipped */
    for (i = 0; i < pem_len; i++) {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }
    real_begin = i + 1; // the character right after \n

    // do not search \n from the exact end, 
    // which may contain one '\n' that we don't want
    // to strip the footer "---- END Public Key -----"
    for (i = pem_len - 5; i >= 0; i--) {
        if (pem[i] == '\n' || pem[i] == '\r') break;
    }
    real_end = i;
    // remove carriage return if any
    for (i = real_begin, j = 0; i < real_end; i++) {
        if (pem[i] != '\n' && pem[i] != '\r') {
            stripped_pem[j] = pem[i];
            j++;
        }
    }
    *real_pem_len = j;
}

int
PEM2DER(const uint8_t *pem_pub, size_t pem_len, uint8_t *der, size_t *der_len)
{
    uint8_t	*pem = NULL;
    int		len = 0;
    int		tlen = 0;
    int		rc = 0;

    if (pem_pub == NULL || pem_len == 0)
        return 1;
    pem = (uint8_t*) malloc(pem_len);
    if (pem == NULL) return 1;
    memset(pem, 0, pem_len);
    PEM_strip((uint8_t*)pem_pub, pem_len, pem, &len);
    if (len <= 0) {
        free(pem);
        return -1;
    }
    tlen = raw_base64_decode(pem, der, 0, &rc);
    free(pem);
    printf("%s: length = %d\n", __func__, tlen);
    if (!rc) {
        *der_len = len;
    }
    return rc;
}


int
cbor_bstr_from_pk_sha(const uint8_t *pub_key,
		      int key_len, cbor_item_t **hash)
{
    uint8_t	pk_sha[SHA512_DIGEST_LENGTH] = {0}; // big enough to hold hash for different algo
    uint8_t	pk_der[PUB_KEY_MAX_SIZE];
    size_t	pk_der_size_byte = 0;
    uint8_t	*temp_sha = NULL;
    size_t	sha_len = 0;
    uint8_t	*ret_sha = NULL;

    memset(pk_der, 0, PUB_KEY_MAX_SIZE);
    if (PEM2DER(pub_key, key_len, pk_der, &pk_der_size_byte)) {
	return -1;
    }
    ret_sha = SHA256(pk_der, pk_der_size_byte, pk_sha);
    sha_len = SHA256_DIGEST_LENGTH;
    if (ret_sha == NULL || memcmp(ret_sha, pk_sha, SHA256_DIGEST_LENGTH)!=0) {
	return -1;
    }
    temp_sha = (uint8_t*)malloc(sha_len);
    if (temp_sha == NULL) {
	return -1;
    }

    memcpy(temp_sha, pk_sha, sha_len);
    cbor_item_t* cbor_bstr = cbor_build_bytestring(temp_sha, sha_len);
    free(temp_sha);
    if (!cbor_bstr) {
        return -1;
    }
    *hash = cbor_bstr;
    return 0;
}

int
make_cbor_pkhash_entry(const uint8_t *p_pub_key, size_t key_size,
            uint8_t **out_hash_entry_buf,
            size_t *out_hash_entry_buf_size)
{
    cbor_item_t* cbor_hash_entry = cbor_new_definite_array(2);
    if (!cbor_hash_entry)
        return -1;
    /* SGX : RA-TLS always generates SHA256 hash over pubkey */
    cbor_item_t* cbor_hash_alg_id = cbor_build_uint8(IANA_HASH_ALG_REGISTRY_SHA256);
    if (!cbor_hash_alg_id) {
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    cbor_item_t* cbor_hash_value;
    int ret = cbor_bstr_from_pk_sha(p_pub_key, key_size, &cbor_hash_value);
    if (ret < 0) {
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return ret;
    }
    int bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_alg_id);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_value);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return -1;
    }
    /* cbor_hash_entry took ownership of hash_alg_id and hash_value cbor items */
    cbor_decref(&cbor_hash_alg_id);
    cbor_decref(&cbor_hash_value);

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    /* for the serialize_alloced buf, we need to free it seperately, as the pointer */
    /* passed to outside invoker, free it in outside invoker */
    cbor_serialize_alloc(cbor_hash_entry, &hash_entry_buf, &hash_entry_buf_size);
    if (!hash_entry_buf)  {
	return -1;
    }
    cbor_decref(&cbor_hash_entry);
    *out_hash_entry_buf = hash_entry_buf;
    *out_hash_entry_buf_size = hash_entry_buf_size;
    return 0;
}


int
make_cbor_claims(uint8_t *pubkey, int pubksz,
		 uint8_t **claims, size_t *csz)
{
    cbor_item_t		*cbor_claims;
    cbor_item_t		*cbor_pubkey_hash_key;
    cbor_item_t		*cbor_pubkey_hash_val;
    uint8_t		*hash_entry_buf;
    size_t		hash_entry_buf_size;
    uint8_t		*claims_buf;
    size_t		claims_bufsz;
    int	rc;

    cbor_claims = cbor_new_definite_map(1);
    cbor_pubkey_hash_key = cbor_build_string("pubkey-hash");
    rc = make_cbor_pkhash_entry(pubkey, pubksz, &hash_entry_buf, &hash_entry_buf_size);
    cbor_pubkey_hash_val = cbor_build_bytestring(hash_entry_buf, hash_entry_buf_size);
    free(hash_entry_buf);
    {
	struct cbor_pair cbor_pubkey_hash_pair =
	    { .key = cbor_pubkey_hash_key,
	      .value = cbor_pubkey_hash_val };
	rc = cbor_map_add(cbor_claims, cbor_pubkey_hash_pair);
    }
    cbor_serialize_alloc(cbor_claims, &claims_buf, &claims_bufsz);
    *claims = claims_buf;
    *csz = claims_bufsz;
    return 0;
}

/*
 * make_cbor_evidence: 
 *	tagged evidence (IANA_CBOR_TAG_INTEL_TEE_QUOTE) contains
 *		cbor quote and claim	
 */
int
make_cbor_evidence(uint8_t *quote, size_t quotesz,
		   uint8_t *claim, size_t claimsz,
		   uint8_t **out_evidence, size_t *evidence_size)
{
    cbor_item_t	*evidence = NULL;
    cbor_item_t	*tagged_evidence = NULL;
    uint8_t	*ebuf;
    size_t	ebufsz;
    int	rc;

    evidence = cbor_new_definite_array(2);
    { /* cbor_evidence: quote and claim bytestring */
	cbor_item_t	*cbor_quote;
	cbor_item_t	*cbor_claims;
	cbor_quote = cbor_build_bytestring(quote, quotesz);
	cbor_claims = cbor_build_bytestring(claim, claimsz);
	rc = cbor_array_push(evidence, cbor_quote);
	rc = cbor_array_push(evidence, cbor_claims);
	cbor_decref(&cbor_claims);
	cbor_decref(&cbor_quote);
    }
    tagged_evidence = cbor_new_tag(IANA_CBOR_TAG_INTEL_TEE_QUOTE);
    cbor_tag_set_item(tagged_evidence, evidence);

    /* tagged evidence is serialized */
    cbor_serialize_alloc(tagged_evidence, &ebuf, &ebufsz);
    cbor_decref(&evidence);
    cbor_decref(&tagged_evidence);
    *out_evidence = ebuf;
    *evidence_size = ebufsz;
    return 0;
}

#if 0
// 
//	TLSRA_CALL0(err0, oid, OBJ_txt2obj("1.2.840.113741.1337.2", 1));
#define TCG_DICE_TAGGED_OID_STR "2.23.133.5.4.9"

#define X509_OID_FOR_QUOTE_STRING "1.2.840.113741.1.13.1"
static const char* oid_sgx_quote = X509_OID_FOR_QUOTE_STRING;
sgx_gen_custom_x509_cert(uint8_t *quote, size_t qz)
{
    ASN1_OBJECT		*obj = NULL;
    ASN1_OCTET_STRING	*data = NULL;
    X509_EXTENSION	*ext = NULL;

    /* oid: quote == evidence */
    TLSRA_CALL0(err0, obj, OBJ_txt2obj(X509_OID_FOR_QUOTE_STRING, 1));
    data = ASN1_OCTET_STRING_new();
    ret = ASN1_OCTET_STRING_set(data, quote, (int)qz);
    /* extension: quote (1 means critical extension */
    X509_EXTENSION_create_by_OBJ(&ext, obj, 1, data);
    ret = X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);
    /* TCG tagged evidence extension */
    cbor_data = ASN1_OCTET_STRING_new();
    ret = ASN1_OCTET_STRING_set(
	cbor_data,
	(const unsigned char*)evidence_buf, (int)evidence_size);
    cbor_obj = OBJ_txt2obj(config->ext_tcg_tagged_oid, 1);
    X509_EXTENSION_create_by_OBJ(&ext, cbor_obj, 0, cbor_data);
    ret = X509_add_ext(x509cert, ext, -1);
}
#endif
/*
 * tee_get_certificate_with_evidence()
 *  calls generate_x509_self_signed_certificate()
 *	calls sgx_gen_custom_x509_cert(config)
 * generate_x509_self_signed_certificate(
 *	const unsigned char* oid, --> config.ext_oid
 *	size_t oid_size,	  --> config.ext_oid_size
 *	const unsigned char* tcg_tagged_oid, --> config.ext_tcg_tagged_oid
 *	size_t tcg_tagged_oid_size,	--> config.ext_tcg_tagged_oid_size
 *	const unsigned char *subject_name, --> config.subject_name
 *	const uint8_t *p_prv_key, --> config.private_key_buf_size
 *	size_t prv_key_size,	--> config.private_key_buf_size
 *	const uint8_t *p_pub_key, --> config.public_key_buf
 *	size_t pub_key_size, --> config.public_key_buf_size
 *	const uint8_t* p_quote_buf, --> config.quote_buf
 *	size_t quote_size,	--> config.quote_buf_size
 *	const uint8_t* p_evidence,	--> config.evidence_buf
 *	size_t evidence_size,	--> config.evidence_size
 *	uint8_t **output_cert,
 *	size_t *output_cert_size)
 */
int
make_certificate_evidence(uint8_t *pubkey, int pubksz,
			  uint8_t *quote, size_t qsz,
			  uint8_t **evidence, size_t *evsz)
{
    uint8_t	*claims = NULL;
    size_t	csz;
    /*
     * cbor claims: pubkey-hash only
     * cbor evidence:
     */
    make_cbor_claims(pubkey, pubksz, &claims, &csz);
    make_cbor_evidence(quote, qsz, claims, csz, evidence, evsz);
}

static void
write_pems(const char *path, X509 *cert, EVP_PKEY *pkey)
{
    FILE	*fp;
    char	buf[1024];

    /* cert */
    strcpy(buf, path);
    strcat(buf, ".pem");
    if ((fp = fopen(buf, "wb")) == NULL) {
	fprintf(stderr, "Cannot open %s\n", buf);
	exit(-1);
    }
    PEM_write_X509(fp, cert);
    fclose(fp);
    /* public key */
    strcpy(buf, path);
    strcat(buf, ".pub");
    if ((fp = fopen(buf, "wb")) == NULL) {
	fprintf(stderr, "Cannot open %s\n", buf);
	exit(-1);
    }
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    /* private key */
    strcpy(buf, path);
    strcat(buf, ".priv");
    if ((fp = fopen(buf, "wb")) == NULL) {
	fprintf(stderr, "Cannot open %s\n", buf);
	exit(-1);
    }
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
}

/*
 * Self-signed Certificate with Quote using X509.Extensions
 *	
 */
static int
make_x509cert(X509 **px509, EVP_PKEY *pkey,
	      uint8_t *quote, int qtsz,
	      uint8_t *evidence, int evsz)
{
    X509	*x509 = NULL;
    int	rc = 0;

    x509 = X509_new();
    /* Version 3 */
    X509_set_version(x509, 2);
    /* serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    /* X509_gmtime_adj() sets the ASN1_TIME structure */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), YEAR_ONE);
#if 0
    X509_set_notBefore(x509, X509_gmtime_adj(NULL, 0));
    X509_set_notAfter(x509, X509_gmtime_adj(NULL, YEAR_ONE));
#endif
    /* Public Key of this Certificate */
    TLSRA_CALL1(err0, rc, X509_set_pubkey(x509, pkey));
    {
	X509V3_CTX ctx;
	/* Set Subject and Issuer Names, the same name for self-signed */
	X509_NAME	*subj = X509_NAME_new();
	X509_NAME_add_entry_by_txt(subj, "C",  MBSTRING_ASC,
				   (unsigned char *)"JP", -1, -1, 0);
	X509_NAME_add_entry_by_txt(subj, "ST",  MBSTRING_ASC,
				   (unsigned char *)"Tokyo", -1, -1, 0);
	X509_NAME_add_entry_by_txt(subj, "L",  MBSTRING_ASC,
				   (unsigned char *)"Chiyoda", -1, -1, 0);
	X509_NAME_add_entry_by_txt(subj, "O",  MBSTRING_ASC,
				   (unsigned char *)"ROIS", -1, -1, 0);
	X509_NAME_add_entry_by_txt(subj, "OU",  MBSTRING_ASC,
				   (unsigned char *)"CRADSEC", -1, -1, 0);
	X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
				   (unsigned char *)"cradsec-srvr_ra", -1, -1, 0);
	/* issuer and subjet are the same */
	TLSRA_CALL1(err0, rc, X509_set_subject_name(x509, subj));
	TLSRA_CALL1(err0, rc, X509_set_issuer_name(x509, subj));
	X509_NAME_free(subj);
	/* making extensions */
	X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
	X509V3_set_ctx_nodb(&ctx); /* openssl.cnf is not used */
	/* basic constraints: CA:false */
	add_ext(x509, NID_basic_constraints, "critical,CA:FALSE", &ctx);
#if 0
	/* keyusages */
	add_ext(x509, NID_key_usage,
		"critical,digitalSignature,keyEncipherment", &ctx);
	add_ext(x509, NID_ext_key_usage, "serverAuth", &ctx);
#endif
	/* subject key identifier */
	add_ext(x509, NID_subject_key_identifier, "hash", &ctx);
	/* authority key identifier */
	add_ext(x509, NID_authority_key_identifier, "keyid:always", &ctx);

	printf("%s: Self-signed certificate\n", __func__);
    }
    /*
     * Extensions
     */
    {	/* quote 1.2.840.113741.1.13.1 */
	/* oid: quote */
	ASN1_OBJECT		*obj = NULL;
	ASN1_OCTET_STRING	*data = NULL;
	X509_EXTENSION		*ext = NULL;
	int	critical = REPORT_CRIT;	/* critical (1) or not (0) */
	/* extension: quote  */
	TLSRA_CALL0(err0, obj, OBJ_txt2obj(X509_OID_FOR_QUOTE_STRING, 1));
	data = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data, quote, qtsz);
	X509_EXTENSION_create_by_OBJ(&ext, obj, critical, data);
	X509_add_ext(x509, ext, -1);
	ASN1_OCTET_STRING_free(data);
	ASN1_OBJECT_free(obj);
	/* extension: TCG tagged evidence */
	data = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data, evidence, evsz);
	TLSRA_CALL0(err0, obj, OBJ_txt2obj(TCG_DICE_TAGGED_OID_STR, 1));
	printf("%s: obj=%p, data=%p\n", __func__, obj, data);
	/* ext is reused */
	X509_EXTENSION_create_by_OBJ(&ext, obj, critical, data);
	printf("%s: ext=%p\n", __func__, ext);
	X509_add_ext(x509, ext, -1);
	ASN1_OCTET_STRING_free(data);
	ASN1_OBJECT_free(obj);
	/* ext is no more used */
	X509_EXTENSION_free(ext);
    }
    /* sign using CA private key or self private key */
    X509_sign(x509, pkey, EVP_sha256());
    *px509 = x509;
    /* successfuly created */
    return 1;
err0:
    printf("%s: error\n", __func__);
    return 0;
}

void
generate_quote(uint8_t **pquote, int *qsz)
{
    *qsz = 512;
    *pquote = (uint8_t*) malloc(*qsz);
}

int
main(int argc, char **argv)
{
    X509	*cert = NULL;
    uint8_t	*pubkey = NULL;
    uint8_t	*privkey = NULL;
    int		pubsz = 0;
    int		privsz = 0;
    uint8_t	*quote;
    int		qsz;
    EVP_PKEY	*pkey;
    uint8_t	*evidence;
    size_t	evsz;
    pkey = make_keypair(&pubkey, &pubsz, &privkey, &privsz);
    printf("pubsz = %d, privsz = %d\n", pubsz, privsz);
    /*
     * 
     * calling quote generation, and then
     */
    generate_quote(&quote, &qsz);
    make_certificate_evidence(pubkey, pubsz,
			      quote, qsz, &evidence, &evsz);
    make_x509cert(&cert, pkey, quote, qsz, evidence, evsz);
    write_pems("mycert", cert, pkey);
    free(quote);
    return 0;
}
