/*
 * libpica-clnt.h
 *	Enclave-side definitions
 */
#include "libpica_common.h"

/*
 * Configuration File Format
 *	Containing procinfo
 */
#define PROCCONF_MAGIC	"PROCCNF"
struct confhead {
    char	magic[sizeof(PROCCONF_MAGIC)];
    int		proc_cnt;	/* procinfo count */
    int		fdig_cnt;	/* fdigest count */
    int		str_size;	/* string size in byte */
};

/*
 * PICA Policy
 *	Examples of the Json format are policy.json and policy-2.json
 */
#define VERIFY_TPM2_QUOTE	0x01
#define VERIFY_TPM2_FRESH	0x02
#define VERIFY_PICA_BINARIES	0x04
#define VERIFY_PICA_CHAIN	0x08
#define VERIFY_PICA_UIDS	0x10
#define VERIFIED_ALL(v)		(((v) & (VERIFY_TPM2_QUOTE|VERIFY_PICA_BINARIES|VERIFY_PICA_CHAIN|VERIFY_PICA_UIDS)) == (VERIFY_TPM2_QUOTE|VERIFY_PICA_BINARIES|VERIFY_PICA_CHAIN|VERIFY_PICA_UIDS))

#define PICA_POLICY_V0_STRING	"PICA-2026-09-15"
#define PICA_POLICY_V1_STRING	"PICA-2026-09-25"
#define PICA_POLICY_UN	0 /* unknown */
#define PICA_POLICY_V0	1 /* "PICA-2026-09-15" */
#define PICA_POLICY_V1	2 /* "PICA-2026-09-25" */
#define PICA_NONE	0
#define PICA_ALLOW	1
#define PICA_DENY	2

struct inv_array {
    int		ichn_cnt;	/* invocation chain count */
    char	**ichain;	/* array of invocation chain */
};

struct pica_stmt {
    char	*sid;		/* sid */
    int		effect;		/* allow or deny */
    char	*exec_path;	/* binary file path */
    int		uid_cnt;	/* uid array count */
    int		*uid;		/* uid array */
    int		act_cnt;	/* action count */
    char	**action;	/* function names */
    int		ary_cnt;	/* array count */
    struct inv_array *iarray;	/* array of invocation chain */
};

struct pica_policy {
    char	*version;
    int		entries;
    struct pica_stmt *stmt;
};

extern void	procinfo_show(struct procinfo *cpif, int proc_cnt);
extern void	picapol_show(struct pica_policy *pp);
extern int	pica_read_config(const char *confpath, struct procinfo	**procinfo);
extern int	pica_read_policy(const char *polpath, struct pica_policy *ppol);
/* who use the following functions ? */
extern void	build_hashtable(struct procinfo *procinfo, int entries);
//extern void	reg_hashtable(int which, void *addr, const char *path);
//extern int	build_conf(uint8_t *buf, struct procinfo **pinfop);

extern int	pica_request_measure(uint8_t *nonce, uint8_t *measure, size_t msz,
				     size_t *sz,   const char *dpath);
extern int	pica_extract_pinfo(uint8_t *picabody, size_t pica_sz,
				   struct procinfo **pinfo);
extern int	pica_reg_config(const char *path, uint8_t *picabody, size_t pica_sz);

/* verifications */
extern int	pica_verify();
extern int	verify_tpm2all(uint8_t *measure, size_t msz, uint8_t *nonce,
			       uint8_t **o_picabody, size_t *o_pica_sz);
extern int	verify_digest(struct procinfo *regpinfo, struct procinfo *freshpinfo);
extern int	verify_binaries(struct procinfo *pinfo, int ent);
extern int	check_ichain(struct pica_stmt *stmt, struct procinfo *pinf, int cnt);
extern int	check_uids(struct pica_stmt *stmt, struct procinfo *pinf, int cnt);
extern void	actions_show(struct pica_stmt *);

extern struct pica_stmt *find_policy(struct pica_policy *, struct procinfo *);

/*
 * No needs to expose APIs 
 */
extern int	extract_tpm2evidence(uint8_t *measure, size_t msz,
				     uint8_t **quote, size_t *q_sz,
				     uint8_t *apphash, TPMT_SIGNATURE *tpm_sig,
				     uint8_t **picabody, size_t *pica_sz);
extern int	verify_tpm2quote_sig(const uint8_t *s_quoted, int sq_size,
				     const TPMT_SIGNATURE *sig, EVP_PKEY *ak_pubkey);
extern int	check_tpm2pcrs(TPMS_ATTEST *tpm_atst, TPMS_ATTEST *reg_atst);
extern int	extract_tpm2attest(const uint8_t *s_quoted, int sq_size, TPMS_ATTEST *tpm_atst);
extern int	check_apphash(uint8_t *picabody, size_t pica_sz,
			      uint8_t *nonce, uint8_t *apphash, uint8_t *udata);


#define EXTRACT_TPM2_QUTE 1
#define EXTRACT_TPM2_SIGN 2
#define EXTRACT_TPM2_APHASH 4
#define IS_EXTRACT_TPM2_ALL(rc)	(((rc) & (EXTRACT_TPM2_QUTE|EXTRACT_TPM2_SIGN|EXTRACT_TPM2_APHASH)) == (EXTRACT_TPM2_QUTE|EXTRACT_TPM2_SIGN|EXTRACT_TPM2_APHASH))
