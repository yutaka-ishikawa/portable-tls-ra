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

#define TLSRA_CALLP(label, val, lib)		\
do {				\
    val = lib;			\
    if (val <= 0) {		\
    	ERR_print_errors_cb(myssl_printerr, NULL);	\
	goto label;		\
    }				\
} while(0)
