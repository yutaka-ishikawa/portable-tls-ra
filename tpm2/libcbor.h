struct fdigest {
    char	*path;
    uint8_t	digest[32];
};

#define PROCINFO_BASE_ENTRIES	10
struct procinfo {
    pid_t	pid;
    pid_t	ppid;
    uid_t	ruid;
    uid_t	rgid;
    uid_t	euid;
    uid_t	egid;
    uid_t	suid;
    uid_t	sgid;
    char	*path;		/* exec path */
    uint8_t	digest[32];	/* digest of exec binary */
    int		count;
    struct fdigest *libs;		/* digest of shared-libraries */
};

extern uint8_t	*mycbor_pack_procchain(pid_t pid, size_t *size);
extern int	mycbor_add_map(cbor_item_t *map, const char *key,
			       const uint8_t *val, size_t sz);
    
/* return value is boolean: true (1) or false (0) */
#define CBORCALL(label, val, lib)	\
do {				\
    val = lib;			\
    if (!val) {			\
	fprintf(stderr, "%s: %s error\n", __func__, #lib);	\
	goto label;		\
    }				\
} while(0)

#define CBORCALLP(label, val, lib)\
do {				\
    val = lib;			\
    if (val == 0) {		\
	fprintf(stderr, "%s: %s error\n", __func__, #lib);	\
	goto label;		\
    }				\
} while(0)

/*
 * return value is size (int): larger than zero
 */
#define CBORCALLS(label, val, lib)		\
do {				\
    val = lib;			\
    if (val > 0) {			\
	fprintf(stderr, "%s: %s error\n", __func__, #lib);	\
	goto label;		\
    }				\
} while(0)

/* this is for cbor_serialize_alloc */
#define CBORCALL_SALLOC(label, val, lib)		\
do {				\
    lib;			\
    if (val == 0) {			\
	fprintf(stderr, "%s: %s error\n", __func__, #lib);	\
	goto label;		\
    }				\
} while(0)
