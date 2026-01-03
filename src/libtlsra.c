#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <crypto/evp.h>
#include <crypto/evp/evp_local.h>
/*
 * OpenSSL source internal interface
 */
/* under $(OPENSSL_SRC)/include */
#include <internal/ssl_unwrap.h>
/* under $(OPSNSSL_SRC) */
#include <ssl/ssl_local.h>
#include <ssl/record/methods/recmethod_local.h>
/*
 */
#include "ptlsra.h"

#define DEBUG	if (dflag)

/*
 * CRITICALITY of EXTENSION
 */
//#define REPORT_CRITICAL
#ifdef REPORT_CRITICAL
#define REPORT_CRIT	1
#else
#define REPORT_CRIT	0
#endif
#define YEAR_ONE	(60L*60L*24L*365L)
#define O_SIZE	1024

static int rflag = 0;
static int dflag = 0;

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

void
TLSRA_show_subject_name(X509 *x509)
{
    X509_NAME	*subj = X509_get_subject_name(x509);
    BIO		*bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    X509_NAME_print_ex(bio_out, subj, 0, XN_FLAG_RFC2253);
    printf("\n");
#if 0
    int		nent = X509_NAME_entry_count(subj);
    int		i;
    char	objbuf[128];

    for (i = 0; i < nent; i++) {
	X509_NAME_ENTRY	*ent = X509_NAME_get_entry(subj, i);
	ASN1_OBJECT	*obj = X509_NAME_ENTRY_get_object(ent); /* OID */
	ASN1_STRING	*data = X509_NAME_ENTRY_get_data(ent);
	unsigned char	*utf8 = NULL;
	int		len;

	OBJ_obj2txt(objbuf, sizeof(objbuf), obj, 1);

	len = ASN1_STRING_to_UTF8(&utf8, data);
	printf("%s = %.*s\n", objbuf, len, utf8);
	OPENSSL_free(utf8);
    }
#endif
}

void
TLSRA_show_issuer_name(X509 *x509)
{
    X509_NAME	*iss = X509_get_issuer_name(x509);
    BIO		*bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    X509_NAME_print_ex(bio_out, iss, 0, XN_FLAG_RFC2253);
    printf("\n");
}


void
TLSRA_show_nonce(SSL *ssl)
{
    unsigned char out[O_SIZE];
    size_t	sz;

    sz = SSL_get_client_random(ssl, out, O_SIZE);
    printf("Client Nonce: size = %ld\n", sz);
    if (sz > 0) {
	dump("\tnonce = ", out, sz);
    } else {
    }
    sz = SSL_get_server_random(ssl, out, O_SIZE);
    printf("Server Nonce: size = %ld\n", sz);
    if (sz > 0) {
	dump("\tnonce = ", out, sz);
    }
}

void
TLSRA_dump_x509(X509 *x509)
{
    unsigned char *der = NULL;
    int len = i2d_X509(x509, &der);
    if (len > 0) {
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	ASN1_parse_dump(bio, der, len, 0, 0);
	BIO_free(bio);
	OPENSSL_free(der);
    }
}


/*
 * Self-signed Certificate
 *	Subject == Issuer
 */
static int
mysslra_x509(X509 **px509, EVP_PKEY **ppkey,
	     const char *ca_crt, const char *ca_pkey,
	     unsigned char *report, int replen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY	*pkey = NULL;
    X509	*x509 = NULL;
    EVP_PKEY	*crtkey = NULL;
    int	rc = 0;

    TLSRA_CALL0(err0, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    if (!ctx) {

	exit(-1);
    }
    TLSRA_CALL1(err0, rc, EVP_PKEY_keygen_init(ctx));
    TLSRA_CALL1(err0, rc, EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072));
    TLSRA_CALL1(err0, rc, EVP_PKEY_keygen(ctx, &pkey));

    *ppkey = pkey;
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
	/* Set Subject and Issuer Names, the same name for self-signed */
	X509_NAME	*subj = X509_get_subject_name(x509);
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
	if (ca_crt) { /* issued by CA whose name is *ca_crt */
	    X509	*cert = NULL;
	    FILE	*fp;
	    X509_NAME	*issue;
	    /* reading CA certificate */
	    if ((fp = fopen(ca_crt, "r")) == NULL) {
		fprintf(stderr, "Error: reading CA cert %s\n", ca_crt);
		perror("fopen");
		return 0;
	    }
	    TLSRA_CALL0(err0, cert, PEM_read_X509(fp, NULL, NULL, NULL));
	    fclose(fp);
	    /* Getting cert subject extension */
	    issue = X509_get_subject_name(cert);
	    TLSRA_CALL1(err0, rc, X509_set_issuer_name(x509, issue));
	    /* reading certificate private key */
	    if ((fp = fopen(ca_pkey, "r")) == NULL) {
		fprintf(stderr, "Error: reading CA private key %s\n", ca_pkey);
		perror("fopen");
		return 0;
	    }
	    crtkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	    fclose(fp);
	    if (!crtkey) {
		ERR_print_errors_fp(stderr);
		return 0;
	    }
	    printf("CA certificate\n");
	} else {
	    /* self signed */
	    {	/* CA */
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:TRUE");
		X509_add_ext(x509, ext, -1);
		X509_EXTENSION_free(ext);
	    }
	    {	/* Certificate Sign CRL Sign */
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "keyCertSign, cRLSign, digitalSignature");
		X509_add_ext(x509, ext, -1);
		X509_EXTENSION_free(ext);
	    }
	    TLSRA_CALL1(err0, rc, X509_set_issuer_name(x509, subj));
	    crtkey = pkey;
	    printf("Self-signed certificate\n");
	}
    }
    /*
     * Extensions
     */
    {	/* report 1.2.840.113741.1337.2 */
	ASN1_OBJECT		*oid;
	ASN1_OCTET_STRING	*val;
	X509_EXTENSION		*ext;
	int	critical = REPORT_CRIT; 	/* critical (1) or not (0) */
	//const unsigned char reportdata[] = "Report Dummy Report Dummy\n";
	/**/
	TLSRA_CALL0(err0, oid, OBJ_txt2obj("1.2.840.113741.1337.2", 1));
	val = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(val, report, replen);
	//ASN1_OCTET_STRING_set(val, reportdata, strlen((char*)reportdata));
	ext = X509_EXTENSION_create_by_OBJ(NULL, oid, critical, val);
	X509_add_ext(x509, ext, -1); /* -1 means append */
	/* free */
	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(val);
	ASN1_OBJECT_free(oid);
    }
    /* sign using CA private key or self private key */
    X509_sign(x509, crtkey, EVP_sha256());
    *px509 = x509;
    /* successfuly created */
    return 1;
err0:
    return 0;
}


/*
 * This is for server side.
 * On the clientHello message, the server certificate is dynamically created.
 */
static int
on_client_hello(SSL *ssl, int *al, void *arg)
{
    unsigned char	report[512];
    int	len;
    int	rc;
    // SSL_set_msg_callback(con, msg_callback);
    printf("Certificate initializaion\n");
    {
	const unsigned char *nonce = NULL;
	/* nonce from client */
	len = SSL_client_hello_get0_random(ssl, &nonce);
	if (len > 0) {
	    dump("\tnonce = ", nonce, len);
	} else {
	    printf("\tNo nonce has been received\n");
	}
	memset(report, 0, sizeof(report));
	memcpy(report, nonce, len > 512 ? 512 : len);
    }
    //TLSRA_CALL1(err3, rc, SSL_use_certificate_file(ssl, "public.key", SSL_FILETYPE_PEM));
    //TLSRA_CALL1(err3, rc, SSL_use_PrivateKey_file(ssl, "private.key", SSL_FILETYPE_PEM));
    if (rflag) {
	X509		*x509;
	EVP_PKEY	*pkey;
	printf("TLS-RA mode\n");
	if (mysslra_x509(&x509, &pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
			 report, len) != 1) {
	    fprintf(stderr, "Cannot generate certificate\n");
	    exit(-1);
	}
	printf("Subject: "); TLSRA_show_subject_name(x509);
	printf("Issuer: "); TLSRA_show_issuer_name(x509);
	TLSRA_CALL1(err3, rc, SSL_use_certificate(ssl, x509));
	TLSRA_CALL1(err3, rc, SSL_use_PrivateKey(ssl, pkey));
    } else {
	TLSRA_CALL1(err3, rc, SSL_use_certificate_file(ssl, "server.crt", SSL_FILETYPE_PEM));
	TLSRA_CALL1(err3, rc, SSL_use_PrivateKey_file(ssl, "server.key", SSL_FILETYPE_PEM));
    }
    /* success */
    return SSL_CLIENT_HELLO_SUCCESS;
err3: /* error */
    return SSL_CLIENT_HELLO_ERROR;
}

static int
mysslra_verify(int ok, X509 *x509, unsigned char *nonce)
{
    const char		*oid_txt = "1.2.840.113741.1337.2";
    ASN1_OBJECT		*target;
    X509_EXTENSION	*ext;
    const ASN1_OCTET_STRING	*oct;
    const unsigned char	*val;
    int		loc;
    int		critical;
    int		len;

    DEBUG {
	fprintf(stderr, "%s: X509 ******************************\n", __func__);
	X509_print_fp(stderr, x509);
    }

    target = OBJ_txt2obj(oid_txt, 1);
    if (target == NULL) {
	fprintf(stderr, "%s: fatal error\n", __func__);
	return 0; /**/
    }
    loc = X509_get_ext_by_OBJ(x509, target, -1);
    if (loc < 0) { /* no extension field of enclave report */
	fprintf(stderr, "%s: No extension field of enclave report\n", __func__);
	ASN1_OBJECT_free(target);
	return ok;
    }
    fprintf(stderr, "%s: Extension field of enclave report\n", __func__);
    ext = X509_get_ext(x509, loc);
    critical = X509_EXTENSION_get_critical(ext);
    oct = X509_EXTENSION_get_data(ext);
    val = ASN1_STRING_get0_data(oct);
    len = ASN1_STRING_length(oct);
    printf("critical = %d  ", critical);
    dump("REPORT: ", val, len);
    ASN1_OBJECT_free(target);
    // ok = 1;
    return ok;
}

/*
 * Server certificate verification
 */
static int
verify(int ok, X509_STORE_CTX *ctx)
{
#define O_SIZE	1024
    X509	*x509;
    SSL		*ssl;
    size_t	sz;
    unsigned char nonce[O_SIZE];

    DEBUG {
	fprintf(stderr, "%s: Server certificate verification\n", __func__);
    }
    x509 = X509_STORE_CTX_get_current_cert(ctx);
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (x509 == NULL || ssl == NULL) {
	fprintf(stderr, "%s: Server Cert verificaion fails.\n", __func__);
	return ok;
    }
    sz = SSL_get_client_random(ssl, nonce, O_SIZE);
    DEBUG { /* debug */
	int	depth = X509_STORE_CTX_get_error_depth(ctx);
	char	subj[256];
	fprintf(stderr, "\tSubject: "); TLSRA_show_subject_name(x509);
	fprintf(stderr, "\tIssuer: "); TLSRA_show_issuer_name(x509);
	fprintf(stderr, "\nServer Nonce: size = %ld\n", sz);
	if (sz > 0) {
	    dump("\tnonce = ", nonce, sz);
	}
	X509_NAME_oneline(X509_get_subject_name(x509), subj, sizeof(subj));
	fprintf(stderr, "\tok=%d depth=%d ok=%d subject=%s\n", ok, depth, ok, subj);
	// myssl_dump_x509(x509);
    }
    ok = mysslra_verify(ok, x509, nonce);
    if (!ok) {
	int err   = X509_STORE_CTX_get_error(ctx);
	fprintf(stderr, "Server Cert verificaion fails.\n\t reason = %s\n",
		X509_verify_cert_error_string(err));
	// myssl_dump_x509(x509);
	fprintf(stderr, "But become OK\n");
	ok = 1;
    }
    return ok;
}

/*
 * This is for client side.
 * On the clientHello message, the server certificate is dynamically created.
 */
static int
on_client_cert(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
#define O_SIZE	1024
    unsigned char	report[512];
    size_t	sz;
    unsigned char	nonce[O_SIZE];

    DEBUG {
	fprintf(stderr, "%s: is called !!!!!!!!!!!!!!!\n", __func__);
    }
    fprintf(stderr, "TLS-RA mode\n");
    /* nonce from client */
    sz = SSL_get_server_random(ssl, nonce, O_SIZE);
    if (sz > 0) {
	dump("\tnonce = ", nonce, sz);
    } else {
	printf("\tNo nonce has been received\n");
    }
    memset(report, 0, sizeof(report));
    memcpy(report, nonce, sz > 512 ? 512 : sz);
    if (mysslra_x509(x509, pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
		     report, sz) != 1) {
	fprintf(stderr, "Cannot generate certificate\n");
	exit(-1);
    }
    fprintf(stderr, "\tSubject: "); TLSRA_show_subject_name(*x509);
    fprintf(stderr, "\tIssuer: "); TLSRA_show_issuer_name(*x509);
    return 1; /* success */
}


void
TLSRA_server_init(SSL_CTX *ctx, int flag)
{
    /*
     * Handling Handshake during client hello message on the server side
     */
    SSL_CTX_set_client_hello_cb(ctx, on_client_hello, NULL);
    rflag = flag;
}

int
TLSRA_client_init(SSL_CTX *ctx, int flag)
{
    int	rc;
    /*
     * Handling Handshake during client hello message
     */
    SSL_CTX_set_client_cert_cb(ctx, on_client_cert);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify);
    SSL_CTX_set_verify_depth(ctx, 10);
    /* Require Server certificate and verification*/
    /* CA cert (PEM) */
    //TLSRA_CALL0(err, rc, SSL_CTX_load_verify_locations(ctx, "./CA/my_ca.crt", NULL));
    TLSRA_CALL0(err, rc, SSL_CTX_load_verify_dir(ctx, "./CA"));
    rflag = flag;
err:
    return rc;
}
