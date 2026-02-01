/*
 *
 * One possible implementation of an end-end secret data during TLS handshake
 * would be using SSL_export_keying_material_early(). But it is only available
 * during PSK resumption with 0-RTT in the V1.3 protocol.
 * Thus, in this implementation, nonces of both client and server are used to
 * implement end-end secret data. Actual implementation is XOR's.
 * Though 
 *	-- yutaka_ishikawa@me.com, 2026/01/08
 */
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
#ifndef SGX_ENCLAVE
#include <crypto/evp/evp_local.h>
#endif
/*
 * OpenSSL source internal interface
 */
/* under $(OPENSSL_SRC)/include */
#ifndef SGX_ENCLAVE
#include <internal/ssl_unwrap.h>
/* under $(OPSNSSL_SRC) */
#include <ssl/ssl_local.h>
#include <ssl/record/methods/recmethod_local.h>
#endif
/*
 */
#include "sgxenv.h"
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

#define BIO_BUF_LEN	1024
static char	bio_buf[BIO_BUF_LEN];
void
TLSRA_show_subject_name(X509 *x509)
{
    X509_NAME	*subj = X509_get_subject_name(x509);
    //BIO		*bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO		*bio_out = BIO_new_mem_buf(bio_buf, BIO_BUF_LEN);

    X509_NAME_print_ex(bio_out, subj, 0, XN_FLAG_RFC2253);
    printf("%s: %s\n", __func__, bio_buf);
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

static int
myssl_printerr(const char *str, size_t len, void *u)
{
    char	*buf = NULL;
    TLSRA_LIBCALL0(err, buf, malloc(len + 1));
    strncpy(buf, str, len);
    buf[len] = 0;
    printf("SSLerror: %s\n", str);
    free(buf);
    return 1;
err:
    printf("%s: cannot allocate memory\n", __func__);
    return 1;
}

void
myssl_shutdown(SSL_CTX *ctx, SSL *ssl)
{
    int	rc, count = 0;
    do {
	rc = SSL_shutdown(ssl);
	count++;
    } while (rc == 0);
    if (count > 1) {
	printf("SSL_shutdown has been issued %d times\n", count);
    }
    if (rc < 0) {
	ERR_print_errors_cb(myssl_printerr, NULL);
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
}

void
TLSRA_show_issuer_name(X509 *x509)
{
    X509_NAME	*iss = X509_get_issuer_name(x509);
    //BIO		*bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO		*bio_out = BIO_new_mem_buf(bio_buf, BIO_BUF_LEN);

    X509_NAME_print_ex(bio_out, iss, 0, XN_FLAG_RFC2253);
    printf("%s\n", bio_buf);
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

#ifndef SGX_ENCLAVE
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
#endif

	    
void
TLSRA_X509_print(X509 *x509)
{
#ifdef SGX_ENCLAVE
    {
	int	rc;
	size_t	wsz;
	BIO	*bio = NULL;
	BUF_MEM *bptr = NULL;
	TLSRA_CALL0(err0, bio, BIO_new(BIO_s_mem()));
	TLSRA_CALL1(err1, rc, X509_print(bio, x509));
	BIO_get_mem_ptr(bio, &bptr);
	if (bptr && bptr->length > 0) {
	    ocall_putn(bptr->data, bptr->length, &wsz);
	}
    err1:
	BIO_free(bio);
    err0:
	return;
    }
#else
    X509_print_fp(stderr, x509);
#endif
}

/*
 * PEM X509 read
 */
#define X509_SIZE	(4*1024)
X509	*
TLSRA_X509_read(const char *fname)
{
    X509	*x509 = NULL;
#if SGX_ENCLAVE
    {
	BIO	*bio = NULL;
	void	*buf = NULL;
	size_t	len = 0;

	TLSRA_LIBCALL0(err0, buf, malloc(X509_SIZE));
	ocall_readfile(fname, buf, X509_SIZE, &len);
	if (len > 0) {
	    TLSRA_CALL0(err1, bio, BIO_new_mem_buf(buf, (int) len));
	    TLSRA_CALL0(err2, x509, PEM_read_bio_X509(bio, NULL, NULL, NULL));
	}
    err2:
	BIO_free(bio);
    err1:
	free(buf);
    err0:
	return x509;
    }
#else
    {
	FILE	*fp;
	if ((fp = fopen(fname, "r")) == NULL) {
	    fprintf(stderr, "Error: reading CA cert %s\n", fname);
	    perror("fopen");
	    return 0;
	}
	TLSRA_CALL0(err1, x509, PEM_read_X509(fp, NULL, NULL, NULL));
    err1:
	fclose(fp);
	return x509;
    }
#endif
}

/*
 * PEM X509 write: return 1 for success, 0 for fail
 */
int
TLSRA_X509_write(const char *fname, X509 *x509)
{
#if SGX_ENCLAVE
    {
	BIO	*bio = NULL;
	void	*buf = NULL;
	int	rc = 0;
	int	sz = 0, wsz;
	int	fd;

	fd = open(fname, O_CREAT|O_RDWR);
	if (fd < 0) goto err0;
	TLSRA_CALL0(err0, bio, BIO_new(BIO_s_mem()));
	TLSRA_CALL1(err1, rc, PEM_write_bio_X509(bio, x509));
	sz = BIO_pending(bio);
	TLSRA_CALL0msg(err1, buf, malloc(sz),
		       "%s: Cannot allocate memory\n", __func__);
	memset(buf, 0, sz);
	rc = BIO_read(bio, buf, sz);
	if (rc != sz) {
	    fprintf(stderr, "%s: Cannot read BIO\n", __func__);
	}
	wsz = write(fd, buf, sz);
		if (wsz != sz) {
	    fprintf(stderr, "%s: Cannot write %s file\n", __func__, fname);
	    rc = 0;
	}
	close(fd);
	free(buf);
    err1:
	BIO_free(bio);
    err0:
	return 0;
    }
#else
    {
	FILE	*fp;
	if ((fp = fopen(fname, "w")) == NULL) {
	    fprintf(stderr, "Error: cannot create CA cert %s\n", fname);
	    perror("fopen");
	    return 0;
	}
	TLSRA_CALL0(err1, x509, PEM_write_X509(fp, NULL, NULL, NULL));
    err1:
	fclose(fp);
	return 1;
    }
#endif
}

/*
 * Public Key write: return 1 for success, 0 for fail
 */
int
TLSRA_PUBKEY_write(const char *fname, EVP_PKEY *pkey)
{
#if SGX_ENCLAVE
    {
	BIO	*bio = NULL;
	void	*buf = NULL;
	int	rc = 0;
	int	sz = 0, wsz;
	int	fd;

	fd = open(fname, O_CREAT|O_RDWR);
	if (fd < 0) goto err0;
	TLSRA_CALL0(err0, bio, BIO_new(BIO_s_mem()));
	TLSRA_CALL1(err1, rc, PEM_write_bio_PUBKEY(bio, pkey));
	sz = BIO_pending(bio);
	TLSRA_CALL0msg(err1, buf, malloc(sz),
		       "%s: Cannot allocate memory\n", __func__);
	memset(buf, 0, sz);
	rc = BIO_read(bio, buf, sz);
	if (rc != sz) {
	    fprintf(stderr, "%s: Cannot read BIO\n", __func__);
	}
	wsz = write(fd, buf, sz);
	if (wsz != sz) {
	    fprintf(stderr, "%s: Cannot write %s file\n", __func__, fname);
	    rc = 0;
	}
	close(fd);
	free(buf);
    err1:
	BIO_free(bio);
    err0:
	return 0;
    }
#else
    {
	FILE	*fp;
	if ((fp = fopen(fname, "w")) == NULL) {
	    fprintf(stderr, "Error: cannot create CA cert %s\n", fname);
	    perror("fopen");
	    return 0;
	}
	TLSRA_CALL0(err1, rc, PEM_write_PUBKEY(fp, pkey));
    err1:
	fclose(fp);
	return 1;
    }
#endif
}

/*
 * Private Key write: return 1 for success, 0 for fail
 */
int
TLSRA_PrivateKey_write(const char *fname, EVP_PKEY *pkey)
{
#if SGX_ENCLAVE
    {
	BIO	*bio = NULL;
	void	*buf = NULL;
	int	rc = 0;
	int	sz = 0, wsz;
	int	fd;

	fd = open(fname, O_CREAT|O_RDWR);
	if (fd < 0) goto err0;
	TLSRA_CALL0(err0, bio, BIO_new(BIO_s_mem()));
	TLSRA_CALL1(err1, rc, PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL));
	sz = BIO_pending(bio);
	TLSRA_CALL0msg(err1, buf, malloc(sz),
		       "%s: Cannot allocate memory\n", __func__);
	memset(buf, 0, sz);
	rc = BIO_read(bio, buf, sz);
	if (rc != sz) {
	    fprintf(stderr, "%s: Cannot read BIO\n", __func__);
	}
	wsz = write(fd, buf, sz);
	if (wsz != sz) {
	    fprintf(stderr, "%s: Cannot write %s file\n", __func__, fname);
	    rc = 0;
	}
	close(fd);
	free(buf);
    err1:
	BIO_free(bio);
    err0:
	return 0;
    }
#else
    {
	FILE	*fp;
	if ((fp = fopen(fname, "w")) == NULL) {
	    fprintf(stderr, "Error: cannot create CA cert %s\n", fname);
	    perror("fopen");
	    return 0;
	}
	TLSRA_CALL0(err1, x509, PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL));
    err1:
	fclose(fp);
	return 1;
    }
#endif
}

#define PEM_SIZE	(4*1024)
EVP_PKEY *
TLSRA_PKEY_read(const char *pkeyfname)
{
    EVP_PKEY	*pkey = NULL;
#ifdef SGX_ENCLAVE
    {
	BIO	*bio = NULL;
	void	*buf = NULL;
	size_t	len = 0;

	TLSRA_LIBCALL0(err0, buf, malloc(PEM_SIZE));
	ocall_readfile(pkeyfname, buf, PEM_SIZE, &len);
	if (len > 0) {
	    TLSRA_CALL0(err1, bio, BIO_new_mem_buf(buf, (int) len));
	    TLSRA_CALL0(err2, pkey, PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL));
	}
    err2:
	BIO_free(bio);
    err1:
	free(buf);
    err0:
	return pkey;
    }
#else
    {
	FILE	*fp;
	if ((fp = fopen(pkeyfname, "r")) == NULL) {
	    fprintf(stderr, "Error: reading CA private key %s\n", pkeyfname);
	    perror("fopen");
	    return 0;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey;
    }
#endif
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
	    X509_NAME	*issue;
	    /* reading CA certificate */
	    cert = TLSRA_X509_read(ca_crt);
	    /* Getting cert subject extension */
	    issue = X509_get_subject_name(cert);
	    TLSRA_CALL1(err0, rc, X509_set_issuer_name(x509, issue));
	    /* reading certificate private key */
	    crtkey = TLSRA_PKEY_read(ca_pkey);
	    if (!crtkey) {
		ERR_print_errors_cb(myssl_printerr, NULL);
		return 0;
	    }
	    printf("%s: CA certificate\n", __func__);
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
	    printf("%s: Self-signed certificate\n", __func__);
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
    printf("Certificate initializaion rflag=%d\n", rflag);
    {
	const unsigned char *nonce = NULL;
	/* nonce from client, it is not needed to free nounce */
	len = SSL_client_hello_get0_random(ssl, &nonce);
	if (len > 0) {
	    dump("\tnonce = ", nonce, len);
	} else {
	    printf("\t%s: No nonce has been received\n", __func__);
	}
	/* making report */
	//len = _TLSRA_makereport(report, 512, nonce);

	memset(report, 0, sizeof(report));
	memcpy(report, nonce, len > 512 ? 512 : len);
    }
    {
    }
    //TLSRA_CALL1(err3, rc, SSL_use_certificate_file(ssl, "public.key", SSL_FILETYPE_PEM));
    //TLSRA_CALL1(err3, rc, SSL_use_PrivateKey_file(ssl, "private.key", SSL_FILETYPE_PEM));
    if (rflag) {
	X509		*x509;
	EVP_PKEY	*pkey;
	printf("%s: TLS-RA mode\n", __func__);
	if (mysslra_x509(&x509, &pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
			 report, len) != 1) {
	    fprintf(stderr, "Cannot generate certificate\n");
	    abort();
	}
	printf("%s: Subject: ", __func__); TLSRA_show_subject_name(x509);
	printf("%s: Issuer: ", __func__); TLSRA_show_issuer_name(x509);
	TLSRA_CALL1(err3, rc, SSL_use_certificate(ssl, x509));
	TLSRA_CALL1(err3, rc, SSL_use_PrivateKey(ssl, pkey));
    } else {
	/* cert and pkey files are assumed PEM format, not ASN1:
	 * e.g., openssl genrsa -out ./server.key 2048
	 *       openssl req -new -key ./server.key -out ./server.csr ...
	 */
	X509	*cert = NULL;
	EVP_PKEY *pkey = NULL;
	cert = TLSRA_X509_read("server.crt");
	TLSRA_CALL1(err3, rc, SSL_use_certificate(ssl, cert));
	printf("%s: DEBUG3\n", __func__);
	pkey = TLSRA_PKEY_read("server.key");
	TLSRA_CALL1(err3, rc, SSL_use_PrivateKey(ssl, pkey));
    }
    printf("%s: SSL_CLIENT_HELLO_SUCCESS\n", __func__);
    /* success */
    return SSL_CLIENT_HELLO_SUCCESS;
err3: /* error */
    printf("%s: SSL_CLIENT_HELLO_ERROR\n", __func__);
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
	TLSRA_X509_print(x509);
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
 * On the clientHello message, the client certificate is dynamically created.
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
    printf("%s: TLS-RA mode for client\n", __func__);
    fprintf(stderr, "TLS-RA mode\n");
    /* nonce from client */
    sz = SSL_get_server_random(ssl, nonce, O_SIZE);
    if (sz > 0) {
	dump("\tnonce = ", nonce, sz);
    } else {
	printf("%s: \tNo nonce has been received\n", __func__);
    }
    memset(report, 0, sizeof(report));
    memcpy(report, nonce, sz > 512 ? 512 : sz);
    if (mysslra_x509(x509, pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
		     report, sz) != 1) {
	fprintf(stderr, "Cannot generate certificate\n");
	abort();
    }
    fprintf(stderr, "\tSubject: "); TLSRA_show_subject_name(*x509);
    fprintf(stderr, "\tIssuer: "); TLSRA_show_issuer_name(*x509);
    return 1; /* success */
}


void
TLSRA_server_init(SSL_CTX *ctx, int flag)
{
    rflag = flag;
    /*
     * Handling Handshake during client hello message on the server side
     */
    SSL_CTX_set_client_hello_cb(ctx, on_client_hello, NULL);
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
