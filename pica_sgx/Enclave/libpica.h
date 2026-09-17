#define VERIFY_TPM2_QUOTE	0x1
#define VERIFY_PICA_BINARIES	0x2
#define VERIFY_PICA_CHAIN	0x4
#define VERIFY_PICA_UIDS	0x8
#define VERIFIED_ALL(v)		(((v) & (VERIFY_TPM2_QUOTE|VERIFY_PICA_BINARIES|VERIFY_PICA_CHAIN|VERIFY_PICA_UIDS)) == (VERIFY_TPM2_QUOTE|VERIFY_PICA_BINARIES|VERIFY_PICA_CHAIN|VERIFY_PICA_UIDS))
#define PICA_NONE	0
#define PICA_ALLOW	1
#define PICA_DENY	2
struct pica_stmt {
    char	*sid;		/* sid */
    int		effect;		/* allow or deny */
    char	*exec_path;	/* binary file path */
    int		uid_cnt;	/* uid array count */
    int		*uid;		/* uid array */
    int		act_cnt;	/* action count */
    char	**action;	/* function names */
    int		ichn_cnt;	/* invocation chain count */
    char	**ichain;	/* invocation chain */
};

struct pica_policy {
    char	*version;
    int		entries;
    struct pica_stmt *stmt;
};

extern void json_parse(struct json_object * const obj, struct pica_policy *pp);
extern void picapol_show(struct pica_policy *pp);

struct procinfo;
extern void build_hashtable(struct procinfo *procinfo, int entries);
extern void reg_hashtable(int which, void *addr, const char *path);
extern int verify_binaries(struct procinfo *pinfo, int ent);
extern int check_ichain(struct pica_stmt *stmt, struct procinfo *pinf, int cnt);
extern int check_uids(struct pica_stmt *stmt, struct procinfo *pinf, int cnt);
extern struct pica_stmt *find_policy(struct pica_policy *, struct procinfo *);
extern void show_actions(struct pica_stmt *);
