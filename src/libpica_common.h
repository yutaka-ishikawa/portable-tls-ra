#ifndef _LIBPICA_COMMON_H
#define _LIBPICA_COMMON_H
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#ifdef SGXENV
#include <pica_sgxenv.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
typedef int pid_t;
typedef unsigned uid_t;
typedef unsigned gid_t;
#else
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#endif

/*
 * procinfo
 */
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

extern int	sflag;
extern int	vflag;

#define DEBUG	if (dflag)
#define VERB_ALL		0xffff
#define VERB_CONF		0x0001
#define VERB_PICA_CONF		0x0002
#define VERB_PICA_POLICY	0x0004
#define VERB_VRFY_ICHAIN	0x0008
#define VERB_VRFY_DIGEST	0x0010
#define VERB_VRFY_TPM2Q		0x0020
#define VERB_PICA_DAEMON	0x0040
#define VERBOSE(LVL)	if (vflag & (LVL))

extern void	hexdump(FILE *, const char *msg, const unsigned char *bf, int size);
extern float	time_to_msec(int64_t st_sec, int64_t st_nsec, int64_t et_sec, int64_t et_nsec);
extern int	hash_extend_sha256(const uint8_t *old_hash, const uint8_t *digest, uint8_t *new_hash);
extern int	comp_pcr_selection(const TPML_PCR_SELECTION *a, const TPML_PCR_SELECTION *b);
extern void	show_tpm2quote_info(const char *msg, TPMS_QUOTE_INFO *qinfo);
extern void	show_procinfo(struct procinfo *cpif, int proc_cnt);
extern void	free_pinfo(struct procinfo *pinfo, int entries);

#endif /* _LIBPICA_COMMON_H */
