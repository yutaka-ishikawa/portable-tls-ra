#define DEFAULT_TCP_PORT	1100
#define DEFAULT_COUNT	1

#define LIBCALL(label, val, lib, fmt, ...)	\
do {				\
    val = lib;			\
    if (val != 0) {		\
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	goto label;		\
    }				\
} while(0)

#define ENCLAVE_CALL(label, val, lib, fmt, ...)	\
do {				\
    val = lib;			\
    if (val != SGX_SUCCESS) {	\
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	goto label;		\
    }				\
} while(0)

extern char	*get_current_dir_name(void);

extern int	getoption(int argc, char **argv);
extern int	makeargs(int argc, char **argv, int **argpos,
			 char **buf, int *buflen);
