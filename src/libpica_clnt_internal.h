
/*
 * Hash Table: Internal use
 */
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
