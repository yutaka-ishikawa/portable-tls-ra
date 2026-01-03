/*
 *  TLS-RA implementation
 *	2025/10/5
 *	Yutaka Ishikawa, CRADSEC
 *	Center for Research and Development on Secure Computer Systems
 *
 *	Adapting the latest internal representation 2026/Jan/03
 */
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include "libsock.h"
#include "libmyssl.h"

/* openssl source internal interface*/
/* under $(OPENSSL_SRC)/include */
#include <internal/ssl_unwrap.h>
/* under $(OPSNSSL_SRC) */
#include <ssl/ssl_local.h>
#include <ssl/record/methods/recmethod_local.h>

#include <crypto/evp.h>
#include <crypto/evp/evp_local.h>
/*
 *  OID
 *	2.5.4.6 = "C"
 *	2.5.4.8 = "ST"
 *	2.5.4.7 = "L"
 *	2.5.4.10 = "O"
 *	2.5.4.11 = "OU"
 *	2.5.4.3 = "CN"
 */

/*
 * CRITICALITY of EXTENSION
 */
//#define REPORT_CRITICAL
#ifdef REPORT_CRITICAL
#define REPORT_CRIT	1
#else
#define REPORT_CRIT	0
#endif

#define O_SIZE	1024
#define YEAR_ONE	(60L*60L*24L*365L)

static void
show_session(SSL_SESSION *ses)
{
    const SSL_CIPHER	*cipher;
    int	i;

    printf("** SSL_SESSION **\n");
    printf("\t ssl_version(%d)\n", ses->ssl_version);
    printf("\t master_key_length(%ld)\n", ses->master_key_length);
    printf("\t master_key: ");
    for (i = 0; i < ses->master_key_length; i++) {
	printf("%x", ses->master_key[i]);
    }
    printf("\n");
    printf("\t peer (%p) X509*\n", ses->peer);
    printf("\t cipher (%p) SSL_CIPHER*\n", ses->cipher);
    cipher = ses->cipher;
    printf("\t\t valid    = %d\n", cipher->valid);
    printf("\t\t name     = %s\n", cipher->name);
    printf("\t\t stdname  = %s\n", cipher->stdname);
    printf("\t\t id       = %x\n", cipher->id);
    printf("\t\t mkey     = %x\n", cipher->algorithm_mkey);
    printf("\t\t mauth     = %x\n", cipher->algorithm_auth);
    printf("\t\t enc     = %x SSL_AES256CCM(%x)\n", cipher->algorithm_enc, 0x00002000U);
    printf("\t\t mac     = %x\n", cipher->algorithm_mac);
    printf("\t cipher_id (%ld) \n", ses->cipher_id);
    printf("\t ext.hostname (%s) \n", ses->ext.hostname);
    printf("\t ext.max_early_data (%d) \n", ses->ext.max_early_data);
}

static void
show_recordlayer(OSSL_RECORD_LAYER *rl, char *prx)
{
    if (rl == NULL) {
	printf("** NULL %s RECORD LAYER ** ????\n", prx);
	return;
    }
    printf("** %p %s RECORD LAYER **\n", rl, prx);
    printf("\t EVP_CIPHER_CTX enc_ctx(%p)->encrypt(%d)\n", rl->enc_ctx, rl->enc_ctx->encrypt);
    printf("\t EVP_MAC_CTX mac_ctx = %p\n", rl->mac_ctx);
    printf("\t             eivlen  = %ld\n", rl->eivlen);
    printf("\t EVP_MD_CTX   md_ctx = %p\n", rl->md_ctx);
    printf("\t COMP_CTX    compctx = %p\n", rl->compctx);
}

void
myssl_inspect(SSL *ssl)
{
    SSL_SESSION	*ses = SSL_get_session(ssl);
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);

    show_session(ses);
    if (s == NULL) {
	printf("** SSL_CONNECTION is NIL\n");
	return;
    }
    show_recordlayer(s->rlayer.rrl, "READ");
    show_recordlayer(s->rlayer.wrl, "WRITE");
}


int
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
 * Self-signed Certificate
 *	Subject == Issuer
 */
int
mysslra_x509(X509 **px509, EVP_PKEY **ppkey,
	     const char *ca_crt, const char *ca_pkey,
	     unsigned char *report, int replen)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY	*pkey = NULL;
    X509	*x509 = NULL;
    EVP_PKEY	*crtkey = NULL;
    int	rc = 0;

    SSL_CALL0(err0, ctx, EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL));
    if (!ctx) {

	exit(-1);
    }
    SSL_CALL1(err0, rc, EVP_PKEY_keygen_init(ctx));
    SSL_CALL1(err0, rc, EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072));
    SSL_CALL1(err0, rc, EVP_PKEY_keygen(ctx, &pkey));

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
    SSL_CALL1(err0, rc, X509_set_pubkey(x509, pkey));
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
	    SSL_CALL0(err0, cert, PEM_read_X509(fp, NULL, NULL, NULL));
	    fclose(fp);
	    /* Getting cert subject extension */
	    issue = X509_get_subject_name(cert);
	    SSL_CALL1(err0, rc, X509_set_issuer_name(x509, issue));
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
	    SSL_CALL1(err0, rc, X509_set_issuer_name(x509, subj));
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
	SSL_CALL0(err0, oid, OBJ_txt2obj("1.2.840.113741.1337.2", 1));
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

void
myssl_show_subject_name(X509 *x509)
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
myssl_show_issuer_name(X509 *x509)
{
    X509_NAME	*iss = X509_get_issuer_name(x509);
    BIO		*bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    X509_NAME_print_ex(bio_out, iss, 0, XN_FLAG_RFC2253);
    printf("\n");
}


void
myssl_show_nonce(SSL *ssl)
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
myssl_dump_x509(X509 *x509)
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

void
myssl_shutdown(SSL_CTX *ctx, SSL *ssl) {
    int	rc, count = 0;
    do {
	rc = SSL_shutdown(ssl);
	count++;
    } while (rc == 0);
    if (count > 1) {
	printf("SSL_shutdown has been issued %d times\n", count);
    }
    if (rc < 0) {
	ERR_print_errors_fp(stderr);
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
}



/*
 * SSL_CONNECTION:
 *    RECORD_LAYER:
 *	 OSSL_RECORD_LAYER:
 *		
 */
int
myssl_enc(SSL *ssl, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    OSSL_RECORD_LAYER	*wrl = s->rlayer.wrl;
    EVP_CIPHER_CTX *ctx = wrl->enc_ctx;
    int	len;
    int	rc;

    {
	fprintf(stderr, "\tQQQQQQQQQQQQ wrl(%p)->iv(%p) \n", wrl, wrl->iv);
	fprintf(stderr, "\tQQQQQQQQQQQQ rrl(%p)->iv(%p) \n", s->rlayer.rrl, s->rlayer.rrl->iv);
	fprintf(stderr, "\tQQQQQQQ out(%p) outl(%p)\n", out, outl);
    }
    /* See tls13_cipher() in tls13_meth.c 
       OSSL_RECORD_LAYER *rl
       enc_ctx = rl->enc_ctx;
       staticiv = rl->iv;
       nonce = rl->nonce;
       if (rl->mac_ctx != NULL)
         nonce_len = EVP_MAC_CTX_get_mac_size(rl->mac_ctx);
       else
         nonce_len = EVP_CIPHER_CTX_get_iv_length(enc_ctx);
       offset = nonce_len - SEQ_NUM_SIZE;
       seq = rl->sequence;
       memcpy(nonce, staticiv, offset);
       for (loop = 0; loop < SEQ_NUM_SIZE; loop++)
	   nonce[offset + loop] = staticiv[offset + loop] ^ seq[loop];
    */
    rc = EVP_CipherInit_ex(ctx, NULL /*cipher*/, NULL /*impl*/, NULL /*key*/, wrl->iv, 1);
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    rc = EVP_EncryptUpdate(ctx, out, &len, in, inl);
    *outl = len;
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    EVP_CipherFinal_ex(ctx, out + *outl, &len);
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    *outl += len;
    return rc;
}

int
myssl_dec(SSL *ssl, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    OSSL_RECORD_LAYER	*rrl = s->rlayer.rrl;
    //OSSL_RECORD_LAYER	*wrl = s->rlayer.wrl;
    EVP_CIPHER_CTX *ctx = rrl->enc_ctx;
    int	len;
    int	rc;

    rc = EVP_CipherInit_ex(ctx, NULL /*cipher*/, NULL /*impl*/, NULL /*key*/, rrl->iv, 0);
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    rc = EVP_DecryptUpdate(ctx, out, &len, in, inl);
    *outl = len;
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    rc = EVP_CipherFinal_ex(ctx, out + *outl, &len);
    if (rc != 1) {
	ERR_print_errors_fp(stderr);
    }
    *outl += len;
    return rc;
}

static   unsigned char	buf[BUF_SIZE], buf2[BUF_SIZE], buf3[BUF_SIZE];


static void
show_buf(unsigned char *bp, int sz)
{
    int	i;
    for (i = 0; i < sz; i++) {
	printf("%c", *(bp + i));
    }
    printf("\n");
}


void myssl_test_encdec(SSL *ssl)
{
    int	wsz = 0, wsz2 = 0;

    combuf_init(buf, 64);
    memset(buf2, '0', 64);
    memset(buf3, '0', 64);
    show_buf(buf, 64);

    myssl_enc(ssl, buf2, &wsz, buf, 64);
    printf("^^^^^^^^^^^ Encrypt write size = %d\n", wsz);
    show_buf(buf2, 64);
    
    myssl_dec(ssl, buf3, &wsz2, buf2, wsz);
    printf("^^^^^^^^^^^^ Decrypt write size = %d\n", wsz2);
    show_buf(buf3, wsz);
}
