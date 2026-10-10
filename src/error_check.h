#ifdef SGXENV
#include "pica_sgxenv.h"
#endif

#define WSIZE_CHECK(lbl, wsz, asz, func)		\
do {							\
    wsz = func;						\
    if ((wsz) != (asz)) {				\
	fprintf(stderr, "Cannot Write a file.\n");	\
	goto lbl;					\
    }							\
} while(0)

#define SYSCALL(lbl, ret, func, ...)			\
do {							\
    ret = func;						\
    if (ret < 0) {					\
	fprintf(stderr, ##__VA_ARGS__);			\
	goto lbl;					\
    }							\
} while(0)

#define TPM2_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != TSS2_RC_SUCCESS) {	\
	tss_error(#command, rc);	\
        goto lbl;			\
    }					\
} while(0)

#define CRYPT_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	fprintf(stderr, "%s: error %s\n", __func__, #command);	\
        goto lbl;			\
    }					\
} while(0)

extern void ERR_print_errors_fp(FILE *);

#define SSL_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != 1) {			\
        myssl_errors();			\
        goto lbl;			\
    }					\
} while(0)

#define SSL_CALLP(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	myssl_errors();			\
        goto lbl;			\
    }					\
} while(0)
