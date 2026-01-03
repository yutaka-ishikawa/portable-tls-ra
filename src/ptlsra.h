/*
 * Portable TLS-RA
 */
#define TLSRA_CALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
    	ERR_print_errors_fp(stderr);\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALL1(label, val, lib) \
do {				\
    val = lib;			\
    if (val != 1) {		\
    	ERR_print_errors_fp(stderr);\
	goto label;		\
    }				\
} while(0)

extern void	TLSRA_server_init(SSL_CTX*, int rflag);
extern int	TLSRA_client_init(SSL_CTX*, int rflag);
extern void	TLSRA_show_nonce(SSL*);
extern void	TLSRA_show_subject_name(X509*);
extern void	TLSRA_show_issuer_name(X509*);
