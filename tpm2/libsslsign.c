#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#define SSL_CALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
    	ERR_print_errors_fp(stderr);\
	goto label;		\
    }				\
} while(0)

#define SSL_CALL1(label, val, lib) \
do {				\
    val = lib;			\
    if (val != 1) {		\
    	ERR_print_errors_fp(stderr);\
	goto label;		\
    }				\
} while(0)

#define SSL_CALLN(label, val, lib) \
do {				\
    val = lib;			\
    if (val <= 0) {		\
    	ERR_print_errors_fp(stderr);\
	goto label;		\
    }				\
} while(0)

/*
 *	valid if return value is 1
 *	invalid or error if not
 */
int
ssl_verify_signature(uint8_t *data, size_t size,
		     uint8_t *sig_data, size_t sig_size,
		     EVP_PKEY *pubkey,
		     int salg, int halg)
{
    EVP_MD		*md = NULL;
    EVP_MD_CTX		*ctx = NULL;
    EVP_PKEY_CTX	*pkey_ctx = NULL;
    unsigned char	*ecdsa_der = NULL;
    size_t		ecdsa_der_size = 0;
    int	rc;

    switch (halg) {
    case HASH_ALG_SHA1: md = EVP_sha1(); break;
    case HASH_ALG_SHA256: md = EVP_sha256(); break;
    case HASH_ALG_SHA386: md = EVP_sha384(); break;
    case HASH_ALG_SHA512: md = EVP_sha512(); break;
    default:
	fprintf(stderr, "%s: unsupported hash alogorithm (0x%x)\n",
		__func__, halg);
	goto err_ext;
    }
    SSL_CALL0(err_ext, ctx, EVP_MD_CTX_new());
    SSL_CALL1(err_ext, rc, EVP_DigestVerifyInit(
		  ctx, &pkey_ctx, md, NULL, ak_pubkey));
    switch (salg) {
    case SIGN_ALG_RSASSA:
	SSL_CALLN(err_ext, rc, EVP_PKEY_CTX_set_rsa_padding(
		      pkey_ctx, RSA_PKCS1_PADDING));
	break;
    case SIGN_ALG_RSAPSS:
	SSL_CALLN(err_ext, rc, EVP_PKEY_CTX_set_rsa_padding(
		      pkey_ctx, RSA_PKCS1_PSS_PADDING));
	SSL_CALLN(err_ext, rc, EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md));
	SSL_CALLN(err_ext, rc, EVP_PKEY_CTX_set_rsa_pss_saltlen(
		      pkey_ctx, RSA_PSS_SALTLEN_AUTO));
	break;
    }
    /**/
    SSL_CALL1(err_ext, rc, EVP_DigestVerifyUpdate(ctx, data, size));
    /*
     * rc = 1 valid
     */
    rc = EVP_DigestVerifyFinal(ctx, sig_data, sig_size);
err_ext:
    if (ctx) EVP_MD_CTX_free(md_ctx);
    return rc;
}

