#define PICA_ENT_CONF_PROCINFO	1 /* from conf file */
#define PICA_ENT_FRESH_PROCINFO	2 /* from Attester Daemon */
#define PICA_ENT_CONF_POLICY	3 /* from policy file */
struct pica_hentry {
    const char	*path;
    int		type;
    union {
	struct procinfo	 *pinfo;
	struct pica_stmt *stmt;
	void		 *addr;
    };
    struct pica_hentry	*next;
};

struct pica_htable {
    uint32_t		hash;
    struct pica_hentry	hentry;
};

#define PROCCONF_MAGIC	"PROCCNF"
struct confhead {
    char	magic[sizeof(PROCCONF_MAGIC)];
    int		proc_cnt;	/* procinfo count */
    int		fdig_cnt;	/* fdigest count */
    int		str_size;	/* string size in byte */
};
/* FIXME: The following definitions are copied from ../../tpm2/libcbor.h */
struct fdigest {
    union {
	char		*path;
	uint64_t	spos;	/* string position */
    };
    uint8_t	digest[32];
};

#define PROCINFO_BASE_ENTRIES	10 /* 10 entries + alpha */
struct procinfo {
    pid_t	pid;
    pid_t	ppid;
    uid_t	ruid;
    uid_t	rgid;
    uid_t	euid;
    uid_t	egid;
    uid_t	suid;
    uid_t	sgid;
    union {
	char	*path;		/* exec path */
	uint64_t spos;		/* string position */
    };
    uint8_t	digest[32];	/* digest of exec binary */
    int		count;
    union {
	struct fdigest *libs;		/* digest of shared-libraries */
	uint64_t	fpos;
    };
};
/*
 * FIXME: The following three macros and two codes are copied from ../../tpm2/libquote.c
 * Note that ERR_print_errors_fp(stderr) is not defined inside Intel Enclave!
 */
#define CRYPT_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	fprintf(stderr, "%s: error %s\n", __func__, #command);	\
        goto lbl;			\
    }					\
} while(0)

#define SSL_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != 1) {			\
	fprintf(stderr, "%s: error %s\n", __func__, #command);	\
        goto lbl;			\
    }					\
} while(0)

#define SSL_CALLP(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc == 0) {			\
	fprintf(stderr, "%s: error %s\n", __func__, #command);	\
        goto lbl;			\
    }					\
} while(0)
