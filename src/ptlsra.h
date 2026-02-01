/*
 * Portable TLS-RA
 */
#define TLSRA_LIBCALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
	goto label;		\
    }				\
} while(0)

#define TLSRA_SYSCALL(label, val, lib, msg)	\
do {				\
    val = lib;			\
    if (val != 0) {		\
	perror(msg);		\
	goto label;		\
    }				\
} while(0)


#define TLSRA_CALL0msg(label, val, lib, ...)	\
do {				\
    val = lib;			\
    if (val == 0) {		\
	fprintf(stderr, ##__VA_ARGS__);	\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALL0(label, val, lib)		\
do {				\
    val = lib;			\
    if (val == 0) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALL1(label, val, lib) \
do {				\
    val = lib;			\
    if (val != 1) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

#define TLSRA_CALLN(label, val, lib)		\
do {				\
    val = lib;			\
    if (val <= 0) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)

extern void	TLSRA_server_init(SSL_CTX*, int rflag);
extern int	TLSRA_client_init(SSL_CTX*, int rflag);
extern void	TLSRA_show_nonce(SSL*);
extern void	TLSRA_show_subject_name(X509*);
extern void	TLSRA_show_issuer_name(X509*);
extern int	TLSRA_X509_write(const char *ppath, X509 *x509);
extern X509	*TLSRA_X509_read(const char *ppath);
extern EVP_PKEY *TLSRA_PKEY_read(const char *pkeyfname);
extern int	TLSRA_PUBKEY_write(const char *path, EVP_PKEY *pkey);
extern int	TLSRA_PrivateKey_write(const char *path, EVP_PKEY *pkey);

#ifdef SGX_ENCLAVE
#include "Enclave_t.h"
extern int printf(const char*, ...);
extern int fprintf(FILE*, const char*, ...);
extern FILE *stderr;
extern void exit(int);
extern void perror(const char *);
extern int fputc(int, FILE*);
extern int open(const char *, int flags, ...);
extern int close(int);
extern ssize_t read(int, void *, size_t);
extern int write(int, const void*, size_t);
#endif
