#ifndef DEBUG
extern int	dflag;
#define	DEBUG	if (dflag)
#endif
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


extern void	myssl_shutdown(SSL_CTX *ctx, SSL *ssl);
extern void	myssl_inspect(SSL*);
extern int	myssl_enc(SSL *ssl, unsigned char *out, int *outl, const unsigned char *in, int inl);
extern int	myssl_dec(SSL *ssl, unsigned char *out, int *outl, const unsigned char *in, int inl);
extern void	myssl_test_encdec(SSL*);
extern void	myssl_show_nonce(SSL*);

extern int	mysslra_x509(X509 **px509, EVP_PKEY **ppkey, const char*, const char*, unsigned char *, int);
extern int	mysslra_verify(int ok, X509 *x509, unsigned char *nonce);
extern void	myssl_dump_x509(X509*);
extern void	myssl_show_subject_name(X509 *x509);
extern void	myssl_show_issuer_name(X509 *x509);

