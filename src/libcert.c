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
#if SGX_ENCLAVE || SGX_ENCLAVE_WITH_TPM2
/* SGX */
#include "sgxenv.h"
#include <sgx_utils.h>
#include <sgx_ql_lib_common.h>
#endif

#include "ptlsra.h"
#include "libcert.h"
#include <cbor.h>


//#define REPORT_CRITICAL
#ifdef REPORT_CRITICAL
#define REPORT_CRIT	1
#else
#define REPORT_CRIT	0
#endif
#define YEAR_ONE	(60L*60L*24L*365L)

int	cert_dflag = 0;
int	cert_vflag = 0;


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
    TLSRA_SSLCALLP(err0, pkey, EVP_PKEY_new());
    TLSRA_SSLCALLP(err1, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
    TLSRA_SSLCALL(err1, rc, EVP_PKEY_keygen_init(ctx));
    TLSRA_SSLCALL(err1, rc, EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1));
     /* Generate key */
    TLSRA_SSLCALL(err_ret, rc, EVP_PKEY_keygen(ctx, &pkey));
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
extern int verify_SGX_evidence(const ASN1_OCTET_STRING *oct,
			       uint8_t *pem_pubkey, size_t pem_pubkeysz, uint8_t*);
extern int verify_SGX_quote(const ASN1_OCTET_STRING *oct,
			    uint8_t *pem_pubkey, size_t pem_pubkeysz, uint8_t*);
struct verify_tab {
    const char	*oid_txt;
    int		(*verify_func)(const ASN1_OCTET_STRING *oct,
			       uint8_t *pem_pubkey, size_t pem_pubkeysz,
			       uint8_t *nonce);
} verify_tab[] = {
    { TCG_DICE_TAGGED_OID_STR, verify_SGX_evidence },
    { X509_OID_FOR_QUOTE_STRING, verify_SGX_quote },
    { 0, 0 }
};

int
verify_contents(X509 *x509, uint8_t *nonce)
{
    int	rc = 0;
    uint8_t	*pubkey = NULL;
    ASN1_OBJECT	*target = NULL;
    int		pubsz = 0;
    EVP_PKEY	*pkey = NULL;
    BIO		*bio = NULL;
    int		i;

    CERT_DEBUG {
	int	nent = X509_get_ext_count(x509);
	fprintf(stderr, "%s: extension count: %d\n", __func__, nent);
    }
    /* extract public key from cert */
    TLSRA_SSLCALLPmsg(err, pkey, X509_get_pubkey(x509),
		      "Cannot get public key from cert");
    TLSRA_SSLCALLP(err, bio, BIO_new(BIO_s_mem()));
    TLSRA_SSLCALL(err, rc, PEM_write_bio_PUBKEY(bio, pkey));
    pubsz = BIO_pending(bio);
    TLSRA_LIBCALLPmsg(err, pubkey, malloc(pubsz + 1),
		      "%s: Cannot allocate memory\n", __func__);
    memset(pubkey, 0, pubsz + 1);
    rc = BIO_read(bio, pubkey, pubsz);
    if (rc != pubsz) {
	fprintf(stderr, "%s: Cannot read %d byte (actual read %d)\n", __func__, pubsz, rc);
    }
    for (i = 0; verify_tab[i].oid_txt != 0; i++) {
	int	loc;
	CERT_DEBUG {
	    fprintf(stderr, "%s: oid=%s\n", __func__, verify_tab[i].oid_txt);
	}
	target = OBJ_txt2obj(verify_tab[i].oid_txt, 1);
	if (target == NULL) continue;
	loc = X509_get_ext_by_OBJ(x509, target, -1);
	if (loc > 0) { /* found */
	    X509_EXTENSION		*ext = X509_get_ext(x509, loc);
	    const ASN1_OCTET_STRING	*oct= X509_EXTENSION_get_data(ext);
	    rc = verify_tab[i].verify_func(oct, pubkey, pubsz, nonce);
	    break;
	}
	ASN1_OBJECT_free(target);
	target = NULL;
    }
err:
    if (bio) BIO_free(bio);
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
    TLSRA_LIBCALLP(err0, pkey, genpkey());
    /* Convert PEM format */
    TLSRA_SSLCALLP(err0, bio, BIO_new(BIO_s_mem()));
    /**/
    TLSRA_SSLCALL(err0, rc, PEM_write_bio_PUBKEY(bio, pkey));
    pubsz = BIO_pending(bio);
    TLSRA_LIBCALLPmsg(err0, pubkey, malloc(pubsz + 1),
		      "%s: cannot alocate memory. size(%d)\n", __func__, pubsz+1);
    memset(pubkey, 0, pubsz + 1);
    rc = BIO_read(bio, pubkey, pubsz);
    if (rc != pubsz) {
	fprintf(stderr, "%s: Cannot read %d byte (actual read %d)\n", __func__, pubsz, rc);
    }
    /* */
    TLSRA_SSLCALL(err0, rc,
		   PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL));
    privsz = BIO_pending(bio);
    TLSRA_LIBCALLPmsg(err0, privkey, malloc(privsz + 1),
		      "%s: cannot alocate memory. size(%d)\n", __func__, privsz+1);
    memset(privkey, 0, privsz + 1);
    rc = BIO_read(bio, privkey, privsz);
    if (rc != privsz) {
	fprintf(stderr, "%s: Cannot read %d byte (actual read %d)\n", __func__, pubsz, rc);
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

#ifdef SGX_ENCLAVE
/*
 * Intel SGX cbor evidence contains:
 *	claims: cbor string("pubkey-hash")
 *	quote: cbor array[2]:
 *			array[0]: quote byte stream
 *			array[1]: cbor claim
 */
int
make_certificate_evidence(uint8_t *pubkey, int pubksz,
			  uint8_t *nonce, int nsize,
			  uint8_t **quote, uint32_t *qsz,
			  uint8_t **evidence, size_t *evsz)
{
    uint8_t	*claims = NULL;
    size_t	csz;
    int		rc;
    quote3_error_t	qrc;
    sgx_report_t	app_report;
    sgx_target_info_t	target_info;
    sgx_report_data_t	report_data = { 0 };

    /*
     * cbor claims: pubkey-hash only
     */
    rc = make_cbor_sgx_claims(pubkey, pubksz, &claims, &csz);
    if (rc < 0) {
	fprintf(stderr, "%s: error during claims creation\n", __func__);
	return -1;
    }
    SHA256(claims, csz, (unsigned char *) &report_data);
    /*
     * claims are used for user report
     */
    /* OCALL to get target info of QE */
    TLSRA_OCALLmsg(err0, rc,
		   sgx_tls_get_qe_target_info_ocall(&qrc, &target_info,
						    sizeof(sgx_target_info_t)),
		  "%s: sgx_tls_get_qe_target_info_ocall error\n", __func__);
    if (qrc != SGX_QL_SUCCESS) {
	fprintf(stderr,
		"%s: sgx_tls_get_qe_target_info_ocall error (qrc=0x%x)\n", __func__, qrc);
	goto err0;
    } else {
	/* for debugging purpose */
	fprintf(stderr,
		"%s: sgx_tls_get_qe_target_info_ocall SUCCESS\n", __func__);
    }
    TLSRA_OCALLmsg(err0, rc,
		   sgx_create_report(&target_info, &report_data, &app_report),
		   "%s: sgx_create_report error\n", __func__);
    TLSRA_OCALLmsg(err0, rc,
		  sgx_tls_get_quote_size_ocall(&qrc, qsz),
		  "%s: sgx_tls_get_quote_size_ocall\n", __func__);
    if (qrc != SGX_QL_SUCCESS) {
	fprintf(stderr,
		"%s: sgx_tls_get_quote_size_ocall\n", __func__);
	goto err0;
    }
    TLSRA_LIBCALLPmsg(err0, *quote, malloc(*qsz), "%s: malloc fails\n", __func__);
    TLSRA_OCALLmsg(err0, rc,
		   sgx_tls_get_quote_ocall(&qrc, &app_report,
					  sizeof(app_report), *quote, *qsz),
		  "%s: sgx_tls_get_quote_ocall error\n", __func__);
    /*
     * cbor evidence: quote and claims are stored as bytestring in array
     *		      this array is tagged with value 60000, Intel Quote only
     */
    rc = make_cbor_sgx_evidence(*quote, *qsz, claims, csz, evidence, evsz,
				IANA_CBOR_TAG_INTEL_TEE_QUOTE);
    if (rc < 0) {
	fprintf(stderr, "%s: error during evidence creation\n", __func__);
	return -1;
    }
    return 0;
err0:
    return -1;
}
#elif SGX_ENCLAVE_WITH_TPM2
/*
 *	sgx-tpm2-evidence = #6.60004([
 *	    sgx-quote: bstr,
 *	    claims-buffer: bstr .cbor enclave-with-tpm2-claims ])
 *	enclave-with-tpm2-claims = {
 *	    "pubkey-hash": bstr .cbor [
 *		hash-alg-id: uint,	    ; 1: SHA-256
 *		pubkey-hash: bstr ],
 *	    “tpm2-quote”:bstr .cbor tpm2-quote
 *	    "once”: bst}
 *	tpm2-quote = [
 *	    quote: bstr,
 *	    sign: bstr,
 *	    app-hash: bstr ]
 */
int
make_certificate_evidence(uint8_t *pubkey, int pubksz,
			  uint8_t *nonce, int nsize,
			  uint8_t **quote, uint32_t *qsz,
			  uint8_t **evidence, size_t *evsz)
{
    uint8_t	*claims = NULL;
    size_t	csz;
    int		rc;
    quote3_error_t	qrc;
    sgx_report_t	app_report;
    sgx_target_info_t	target_info;
    sgx_report_data_t	report_data = { 0 };

    /*
     *
     */
    fprintf(stderr, "%s: enter LINE=%d\n", __func__, __LINE__);
    make_cbor_tpm2_claims_from_enclave(pubkey, pubksz, nonce, nsize,
				       &claims, &csz);
    fprintf(stderr, "%s: YIIIII CLAIMS csz = %ld LINE=%d\n", __func__, csz, __LINE__);
    SHA256(claims, csz, (unsigned char *) &report_data);
    /*
     * claims are used for user report
     */
    /* OCALL to get target info of QE */
    fprintf(stderr, "%s: LINE=%d\n", __func__, __LINE__);
    TLSRA_OCALLmsg(err0, rc,
		   sgx_tls_get_qe_target_info_ocall(&qrc, &target_info,
						    sizeof(sgx_target_info_t)),
		   "%s: sgx_tls_get_qe_target_info_ocall error\n", __func__);
    if (qrc != SGX_QL_SUCCESS) {
	fprintf(stderr,
		"%s: sgx_tls_get_qe_target_info_ocall error (qrc=0x%x)\n", __func__, qrc);
	goto err0;
    } else {
	/* for debugging purpose */
	fprintf(stderr,
		"%s: sgx_tls_get_qe_target_info_ocall SUCCESS\n", __func__);
    }
    TLSRA_OCALLmsg(err0, rc,
		   sgx_create_report(&target_info, &report_data, &app_report),
		   "%s: sgx_create_report error\n", __func__);
    TLSRA_OCALLmsg(err0, rc,
		   sgx_tls_get_quote_size_ocall(&qrc, qsz),
		   "%s: sgx_tls_get_quote_size_ocall\n", __func__);
    if (qrc != SGX_QL_SUCCESS) {
	fprintf(stderr,
		"%s: sgx_tls_get_quote_size_ocall\n", __func__);
	goto err0;
    }
    /*
     * *quote is type sgx_quote3_t.
     */
    TLSRA_LIBCALLPmsg(err0, *quote, malloc(*qsz), "%s: malloc fails\n", __func__);
    TLSRA_OCALLmsg(err0, rc,
		   sgx_tls_get_quote_ocall(&qrc, &app_report,
					   sizeof(app_report), *quote, *qsz),
		   "%s: sgx_tls_get_quote_ocall error\n", __func__);
    /*
     * cbor evidence: quote and claims are stored as bytestring in array
     *		      this array is tagged with value 60004, Intel Quote with TPM2
     */
    rc = make_cbor_sgx_evidence(*quote, *qsz, claims, csz, evidence, evsz,
				LOCAL_CBOR_TAG_INTEL_TEE_TPM2_QUOTE);
    if (rc < 0) {
	fprintf(stderr, "%s: error during evidence creation\n", __func__);
	return -1;
    }
    return 0;
err0:
    return -1;
}
#else
/*
 * TPM2
 */
#include "libquote.h"
#include "tss2/tss2_tpm2_types.h"
extern int
make_cbor_tri_tpm2_evidence(uint8_t *quote, size_t quotesz,
			    uint8_t *claim, size_t claimsz,
			    uint8_t **out_evidence, size_t *evidence_size);
/*
 * make_certificate_evidence:
 *		[IN]  uint8_t *pubkey, int pubksz,
 *				pubkey must be PEM format
 *		[IN]  uint8_t *nonce, int nsize,
 *		[OUT] uint8_t **quote, uint32_t *qsz,
 *		[OUT] uint8_t **evidence, size_t *evsz
 */
int
make_certificate_evidence(uint8_t *pubkey, int pubksz,
			  uint8_t *nonce, int nsize,
			  uint8_t **quote, uint32_t *qsz,
			  uint8_t **evidence, size_t *evsz)
{
    uint8_t	*claims;
    size_t	csz;
    uint8_t	digest[SHA256_DIGEST_LENGTH];
    uint8_t	pcrs[] = { 1, 2, 3, 4, 5, 6, 7, 10 };
    int		count = 8;
    struct tpm2_quote	tquote;
    int rc;

    /*
     * claims: Cbor map (3)
     *		"public-key":
     *		"nonce":
     */
    rc = make_cbor_tpm2_claims(pubkey, pubksz, nonce, nsize, &claims, &csz);
    if (rc < 0) {
	fprintf(stderr, "%s: error during claims creation\n", __func__);
	return -1;
    }
    /**/
    SHA256(claims, csz, (unsigned char *) digest);
    make_tpm2_quote(digest, SHA256_DIGEST_LENGTH,
		    TPM2_ALG_SHA256, pcrs, count, 0x81018001,
		    &tquote);
    rc = make_cbor_tpm2_evidence(*quote, *qsz,
				 NULL, 0, evidence, evsz);
    if (rc < 0) {
	fprintf(stderr, "%s: error during evidence creation\n", __func__);
    }
    return rc;
}
#endif

static void
write_pems(const char *path, X509 *cert, EVP_PKEY *pkey)
{
    char	buf[1024];

    CERT_DEBUG {
	fprintf(stderr, "%s: %s\n", __func__, path);
    }
    /* cert */
    strncpy(buf, path, 1024); strncat(buf, ".pem", 1023);
    TLSRA_X509_write(buf, cert);
    /* public key */
    strncpy(buf, path, 1024); strncat(buf, ".pub", 1023);
    TLSRA_PUBKEY_write(buf, pkey);
    //PEM_write_PUBKEY(fp, pkey);

    /* private key */
    strncpy(buf, path, 1024); strncat(buf, ".priv", 1023);
    TLSRA_PrivateKey_write(buf, pkey);
    // PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
}

static void
read_pems(const char *path, X509 **pcert)
{
    //FILE	*fp;
    char	buf[1024];

    /* cert */
    strncpy(buf, path, 1024);  strncat(buf, ".pem", 1023);
    *pcert = TLSRA_X509_read(buf);
}

/*
 * Self-signed Certificate with Quote using X509.Extensions
 *	
 */
int
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
    TLSRA_SSLCALL(err0, rc, X509_set_pubkey(x509, pkey));
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
	TLSRA_SSLCALL(err0, rc, X509_set_subject_name(x509, subj));
	TLSRA_SSLCALL(err0, rc, X509_set_issuer_name(x509, subj));
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
	CERT_DEBUG {
	    fprintf(stderr, "%s: Self-signed certificate\n", __func__);
	}
    }
    /*
     * Extensions
     */
    if (quote || evidence) {	/* quote 1.2.840.113741.1.13.1 */
	/* oid: quote */
	ASN1_OBJECT		*obj = NULL;
	ASN1_OCTET_STRING	*data = NULL;
	X509_EXTENSION		*ext = NULL;
	int	critical = REPORT_CRIT;	/* critical (1) or not (0) */
	/* extension: SGX quote  */
	TLSRA_LIBCALLP(err0, obj, OBJ_txt2obj(X509_OID_FOR_QUOTE_STRING, 1));
	data = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data, quote, qtsz);
	X509_EXTENSION_create_by_OBJ(&ext, obj, critical, data);
	X509_add_ext(x509, ext, -1);
	ASN1_OCTET_STRING_free(data);
	ASN1_OBJECT_free(obj);
	/* extension: TCG tagged evidence */
	data = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data, evidence, evsz);
	TLSRA_LIBCALLP(err0, obj, OBJ_txt2obj(TCG_DICE_TAGGED_OID_STR, 1));
	/* ext is reused */
	X509_EXTENSION_create_by_OBJ(&ext, obj, critical, data);
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
    fprintf(stderr, "%s: error\n", __func__);
    return 0;
}


/*
 * A revocation list is not required, and thus no X509_STORE_add_crl() calls
 * nor X509_STORE_set_flags() calls
 */
int
verify_cert(X509 *x509, uint8_t *nonce)
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
#if 0
    {
	X509_VERIFY_PARAM *param;
	struct _X509_VERIFY_PARAM_st { /* copy from crypto/x509/x509_local.h */
	    char *name;
	    time_t check_time;    /* Time to use */
	    uint32_t inh_flags;   /* Inheritance flags */
	    unsigned long flags;  /* Various verify flags */
	    int purpose;          /* purpose to check untrusted certificates */
	    int trust;            /* trust setting to check */
	    int depth;            /* Verify depth */
	    int auth_level;       /* Security level for chain verification */
	    /* more definition below */
	} *iprm;

	param = X509_STORE_CTX_get0_param(ctx);
	iprm = (struct _X509_VERIFY_PARAM_st*) param;
	fprintf(stderr, "%s:X509_STORE_CTX\n", __func__);
	fprintf(stderr, "\tname=%s\n", iprm->name);
	fprintf(stderr, "\tflags=0x%lx\n", iprm->flags);
	fprintf(stderr, "%s: calling X509_verify_cert\n", __func__);
    }
#endif
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
    rc = verify_contents(x509, nonce);
err:
    return rc;
}

//#define LIBCERT_TEST
#ifdef LIBCERT_TEST
/*
 *
 */
void
mygetopt(int argc, char **argv)
{
    int	i;
    for (i = 1; i < argc; i++) {
	switch (argv[i][1]) {
	case 'd': cert_dflag = 1; break;
	case 'v': cert_vflag = 1; break;
	}
    }
}

int
main(int argc, char **argv)
{
    X509	*cert = NULL;
    uint8_t	*pubkey = NULL;
    uint8_t	*privkey = NULL;
    int		pubsz = 0;
    int		privsz = 0;
    uint8_t	*quote = NULL;
    uint32_t	qsz = 0;
    EVP_PKEY	*pkey;
    uint8_t	*evidence;
    size_t	evsz;
    int		opt, rc;

    mygetopt(argc, argv);
    pkey = make_keypair(&pubkey, &pubsz, &privkey, &privsz);
    CERT_DEBUG {
	fprintf(stderr, "pubsz = %d, privsz = %d\n", pubsz, privsz);
    }
    /*
     * quote and evidence are created
     */
    rc = make_certificate_evidence(pubkey, pubsz,
				   nonce,
				   &quote, &qsz, &evidence, &evsz);
    if (rc == 0) {
	printf("Certificate evidence has been created successfuly.\n");
    } else {
	printf("Creation of certificate evidence failed.\n");
    }
    /*
     * quote and evidence are stored in certificate extension field
     */
    make_x509cert(&cert, pkey, quote, qsz, evidence, evsz);
    write_pems("mycert", cert, pkey);
    X509_free(cert);
    free(quote);
    CERT_DEBUG {
	fprintf(stderr, "my certificaion is freed\n");
    }
    /*
     *
     */
    CERT_DEBUG {
	fprintf(stderr, "my certificaion is read and verified\n");
    }
    read_pems("mycert", &cert);
    if (cert == NULL) {
	printf("Cannot read cert file\n");
	return 0;
    }
    if (verify_cert(cert) & (VERIFIED_QUOTE|VERIFIED_EVIDENCE)) {
	printf("Verification success.\n");
    } else {
	printf("Verification error.\n");
    }
    return 0;
}
#endif
