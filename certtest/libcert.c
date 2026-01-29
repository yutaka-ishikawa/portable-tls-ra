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

/*
 * system dependent verification table
 */
#define VERIFIED_QUOTE		0x01
#define VERIFIED_EVIDENCE	0x02

int
verify_SGX_quote(const ASN1_OCTET_STRING *oct)
{
    int			sz  = ASN1_STRING_length(oct);
    const uint8_t	*quote = ASN1_STRING_get0_data(oct);

    /* quote is extracted */
    fprintf(stderr, "%s: called size(%d)\n", __func__, sz);
    return VERIFIED_QUOTE;
}

/*
 * SGX evidence: quote and claims
 *		tag: IANA_CBOR_TAG_INTEL_TEE_QUOTE
 */
int
verify_SGX_evidence(const ASN1_OCTET_STRING *oct)
{
    int			sz = ASN1_STRING_length(oct);
    const uint8_t	*evi = ASN1_STRING_get0_data(oct);
    cbor_item_t		*cbor_evi = NULL;
    struct cbor_load_result	cborload;
    cbor_item_t		*itm = NULL;
    fprintf(stderr, "%s: called oct size(%d)\n", __func__, sz);
    itm = cbor_load(evi, sz, &cborload);
    printf("%s: itm = %p\n", __func__, itm);
    if (cborload.error.code != CBOR_ERR_NONE) {
	fprintf(stderr, "%s: cbor_load failed\n", __func__);
	goto err;
    }
    /* IANA_CBOR_TAG_INTEL_TEE_QUOTE == TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG */
    if (cbor_tag_value(itm) != IANA_CBOR_TAG_INTEL_TEE_QUOTE) {
	fprintf(stderr, "%s: cbor is not INTEL QUOTE\n", __func__);
	goto err;
    }
    cbor_evi = cbor_tag_item(itm);
    if (cbor_evi == NULL || !cbor_isa_array(cbor_evi)) {
	fprintf(stderr, "%s: cbor is corrupted\n", __func__);
	goto err;
    }
    {
	int		sz;
	cbor_item_t	*cbor_quote = NULL;
	uint8_t		*quote;
	size_t		quote_sz;
	cbor_item_t	*cbor_claims = NULL;
	uint8_t		*claims = NULL;
	size_t		claims_sz = 0;

	sz = cbor_array_size(cbor_evi);
	if (sz != 2) {
	    fprintf(stderr, "%s: expected array size is 2, but %d\n", __func__, sz);
	    goto err;
	}
	/* quote is stored in index 0 */
	cbor_quote = cbor_array_get(cbor_evi, 0);
	if (!cbor_quote || !cbor_isa_bytestring(cbor_quote)) {
	    fprintf(stderr, "%s: byte string is expected\n", __func__);
	    goto err;
	}
	quote  = cbor_bytestring_handle(cbor_quote);
	quote_sz = cbor_bytestring_length(cbor_quote);
	printf("quote = %p quote_sz = %ld\n", quote, quote_sz);

	/* claims is stored in index 1 */
	cbor_claims = cbor_array_get(cbor_evi, 1);
	if (!cbor_claims || !cbor_isa_bytestring(cbor_claims)) {
	    fprintf(stderr, "%s: byte string is expected\n", __func__);
	    goto err;
	}
	claims  = cbor_bytestring_handle(cbor_claims);
	claims_sz = cbor_bytestring_length(cbor_claims);
	printf("claims = %p claims_sz = %ld\n", claims, claims_sz);
	{
	    extern int sgx_tls_compare_quote_hash(uint8_t*, uint8_t*, size_t);
	    int rc = sgx_tls_compare_quote_hash(quote, claims, claims_sz);
	    if (rc != 0) {
		printf("%s: quote hash error\n", __func__);
	    }
	}
    }
    return VERIFIED_EVIDENCE;
err:
    return 0;
}

struct verify_tab {
    const char	*oid_txt;
    int		(*verify_func)(const ASN1_OCTET_STRING *oct);
} verify_tab[] = {
    { X509_OID_FOR_QUOTE_STRING, verify_SGX_quote },
    { TCG_DICE_TAGGED_OID_STR, verify_SGX_evidence },
    { 0, 0 }
};

int
verify_contents(X509 *x509)
{
    int	rc = 0;
    ASN1_OBJECT		*target = NULL;
    int nent, i;

    nent = X509_get_ext_count(x509);
    printf("%s: extension count: %d\n", __func__, nent);

    for (i = 0; verify_tab[i].oid_txt != 0; i++) {
	int	loc;
	printf("%s: oid=%s\n", __func__, verify_tab[i].oid_txt);
	target = OBJ_txt2obj(verify_tab[i].oid_txt, 1);
	if (target == NULL) continue;
	loc = X509_get_ext_by_OBJ(x509, target, -1);
	if (loc > 0) { /* found */
	    X509_EXTENSION *ext = X509_get_ext(x509, loc);
	    const ASN1_OCTET_STRING *oct= X509_EXTENSION_get_data(ext);
	    rc |= verify_tab[i].verify_func(oct);
	}
	ASN1_OBJECT_free(target);
	target = NULL;
    }
err:
    if (target) ASN1_OBJECT_free(target);
    return rc;
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


/*
 * Intel SGX cbor evidence contains:
 *	claims: cbor string("pubkey-hash")
 *	quote: cbor array[2]:
 *			array[0]: quote byte stream
 *			array[1]: cbor claim
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
     */
    make_cbor_sgx_claims(pubkey, pubksz, &claims, &csz);
    /*
     * cbor evidence: quote and claim are stored as bytestring in array
     *		      this array is tagged with value 60000
     */
    make_cbor_sgx_evidence(quote, qsz, claims, csz, evidence, evsz);
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

static void
read_pems(const char *path, X509 **pcert)
{
    FILE	*fp;
    char	buf[1024];

    /* cert */
    strcpy(buf, path);
    strcat(buf, ".pem");
    if ((fp = fopen(buf, "rb")) == NULL) {
	fprintf(stderr, "Cannot open %s\n", buf);
	exit(-1);
    }
    /* cert is created from file */
    *pcert = PEM_read_X509(fp, NULL, NULL, NULL);
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
	/* extension: SGX quote  */
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

/*
 * A revocation list is not required, and thus no X509_STORE_add_crl() calls
 * nor X509_STORE_set_flags() calls
 */
int
verify_cert(X509 *x509)
{
    X509_STORE_CTX	*ctx = NULL;
    X509_STORE		*store = NULL;
    int	rc = 0;

    /* context for verification */
    ctx = X509_STORE_CTX_new();
    store = X509_STORE_new();
    X509_STORE_CTX_init(ctx, store, NULL, NULL);

    X509_STORE_CTX_set_cert(ctx, x509);
    X509_STORE_add_cert(store, x509);
    if (X509_verify_cert(ctx) != 1) {
	int err = X509_STORE_CTX_get_error(ctx);
	const char *msg = X509_verify_cert_error_string(err);
	fprintf(stderr, "X509_verify_cert failed: %s (code=%d)\n", msg, err);
	rc = -1;
	goto err;
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    /* Checking quote: system dependent */
    rc = verify_contents(x509);
err:
    return rc;
}

/*
 *
 */
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
#if 0
    X509_free(cert);
    free(quote);
    /*
     *
     */
    read_pems("mycert", &cert);
#endif
    if (verify_cert(cert) & (VERIFIED_QUOTE|VERIFIED_EVIDENCE)) {
	printf("Verify success\n");
    } else {
	printf("Verify error\n");
    }
    return 0;
}
