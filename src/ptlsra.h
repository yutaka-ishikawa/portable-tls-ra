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

#ifdef SGX_ENCLAVE
#include "Enclave_t.h"
typedef struct FILE FILE;
extern int printf(const char*, ...);
extern int fprintf(FILE*, const char*, ...);
extern FILE *stderr;
extern void exit(int);
extern void perror(const char *);
extern int fputc(int, FILE*);
#endif
