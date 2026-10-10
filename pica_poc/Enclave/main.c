#include <stdint.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>

#include <openssl/types.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

#include "libio.h"
#include "libutil.h"
#include "libpica_clnt.h"
#include <sgx_error.h>
#include <sgx_trts.h>

#define PICA_POLICY_PATH	"./policy.json"
#define PICA_CONF_PATH		"./pica.conf"
#define PICA_DAEMON_PATH	"/tmp/sock-tpmd-daemon"

int	dflag = 0;
int	eflag = 0;
int	rflag = 0;
int	sflag = 0;
int	vflag = 0;
char	*pol_path;
char	*pconf_path;
char	*pdaemon_path;

#define OPT_GET_STRVAL(dst, len, pos, argc, argv, lbl) \
do {						\
    if ((pos + 1) >= argc) goto lbl;		\
    dst = strndup(argv[pos+1], len); pos++;	\
} while(0);

static uint32_t
opt_get_xval(int *flg, int *pos, int argc, char **argv)
{
    char	*cp = argv[*pos+1];
    uint32_t	val = 0;
    int	rc;

    if ((*pos + 1) >= argc
	|| cp[0] != '0' || (cp[1] != 'x' && cp[1] != 'X')) return -1;
    cp += 2;
    if (*cp == '\0')  return -1;
    while (*cp != '\0') {
        unsigned char	ch = (unsigned char)*cp;
        if (isdigit(ch)) {
	    ch = ch - '0';
	} else if (isxdigit(ch)) {
	    ch = islower(ch) ?  (ch - 'a' + 10) : (ch - 'A' + 10);
	}
        val = val*16 + ch;
	cp++;
    }
    *pos += 1;
    *flg = val;
    return rc;
}

static void
usage(const char *cmd)
{
    fprintf(stderr, "%s: -h : producing this message\n", cmd);
    fprintf(stderr, "    -D <daemon path> : specifying attester daemon path%s", "\n");
    fprintf(stderr, "                     : e.g., -D /tmp/sock-tpmd-daemon%s",  "\n");
    fprintf(stderr, "    -r <conf path>   : registering configuration file%s", "\n");
    fprintf(stderr, "                     : e.g., -r pica.conf%s", "\n");
    fprintf(stderr, "    -p <policy path> : specifying policy file path%s", "\n");
    fprintf(stderr, "                     : e.g., -p policy.json (default)%s", "\n");
    fprintf(stderr, "    -d : for debugging%s", "\n");
}

static int
getoption(int argc, char **argv)
{
    int	i;

    for (i = 1; i < argc; i++) {
	//printf("argv[%d] = %s\n", i, argv[i]);
	if (argv[i][0] == '-') {
	    switch (argv[i][1]) {
	    case 'h':
		goto err;
	    case 'd':
		dflag = 1; break;
	    case 'D': /* using Attester Daemon */
		OPT_GET_STRVAL(pdaemon_path, 108, i, argc, argv, err);
		break;
	    case 'r': /* registering mode: writing configuration file */
		OPT_GET_STRVAL(pconf_path, 1024, i, argc, argv, err);
		rflag = 1;
		break;
	    case 'p': /* policy file */
		OPT_GET_STRVAL(pol_path, 1024, i, argc, argv, err);
		break;
	    case 'e': /* skip pica */
	    case 'E': /* skip pica */
		eflag = 1;
		break;
	    case 'v':
		if (opt_get_xval(&vflag, &i, argc, argv) <= 0) goto err;
		printf("vflag is set to 0x%x\n", vflag); break;
	    case 's':
		sflag = 1; break;
	    }
	} else {
	    break;
	}
    }
    if (pol_path == NULL) pol_path = strndup(PICA_POLICY_PATH, sizeof(PICA_POLICY_PATH));
    if (pconf_path == NULL) pconf_path = strndup(PICA_CONF_PATH, sizeof(PICA_CONF_PATH));
    if (pdaemon_path == NULL) pdaemon_path = strndup(PICA_DAEMON_PATH, sizeof(PICA_DAEMON_PATH));
    return i;
err:
    usage(argv[0]);
    return -1;
}

int
main(int argc, char **argv)
{
    int	rc;
    struct procinfo	*procinfo;
    struct pica_policy	ppol;
    int	entries;
    uint8_t	nonce[32];
    uint8_t	measure[1024*128];
    size_t	msz = sizeof(measure);
    uint8_t	*picabody;
    size_t	pica_sz;
    sgx_status_t    sret;
    int	verified = 0;
    int64_t	st_sec, st_nsec, et_sec, et_nsec;
    int64_t	mt_sec, mt_nsec;
	
    printf("%s: argc = %d\n", __func__, argc);
    rc = getoption(argc, argv);
    if (rc < 0) goto err_exit;
    printf("daemon path: %s\n", pdaemon_path);
    printf("policy path: %s\n", pol_path);
    printf("configuration path: %s\n", pconf_path);

    getclocktime(&st_sec, &st_nsec);
    if (rflag) {
	printf("!!!!!! REGISTRATION MODE !!!!!!!\n");
    } else {
	/* procinfo from conf file */
	entries = pica_read_config(pconf_path, &procinfo);
	if (entries == 0) {
	    printf("Cannot read configuration file: %s\n", pconf_path);
	    goto err_exit;
	}
	// procinfo_show(procinfo, entries);
    }
    /* policy read */
    memset(&ppol, 0, sizeof(ppol));
    rc = pica_read_policy(pol_path, &ppol);
    if (rc < 0) {
	printf("Cannot read policy file: %s\n", pol_path);
	goto err_exit;
    }
    /*
     *
     */
    getclocktime(&mt_sec, &mt_nsec);
    sret = sgx_read_rand((unsigned char *)nonce, sizeof(nonce));
    if (sret != SGX_SUCCESS) goto err_exit;
    /*
     * Talking to Attester Daemon to obtain measurement results
     */
    memset(measure, 0, msz);
    sret = pica_request_measure(nonce, measure, sizeof(measure), &msz, pdaemon_path);
    printf("%s: return\n", __func__);
    if (sret != SGX_SUCCESS) {
	printf("%s: ocall_pica_measure error sret=0x%x\n", __func__, sret);
	return -1;
    }
    /*
     * Verify TPM2 attestated evidences
     */
    verified = pica_verify_tpm2all(measure, msz, nonce, &picabody, &pica_sz);
    printf("%s: rc = %d picabody(%p), pica_sz(%ld)\n", __func__, rc, picabody, pica_sz);

    if (rflag) {
	/* registration mode */
	printf("%s: registration mode\n", __func__);
	pica_reg_config(pconf_path, picabody, pica_sz);
	return 0;
    }
    {
	struct procinfo	*fresh_pinfo;
	struct procinfo	*mybinary;
	int	fresh_pent;
	struct pica_stmt	*pstmt;

	fresh_pent = pica_extract_pinfo(picabody, pica_sz, &fresh_pinfo);

	/* proc_fresh is generated from Attester Daemon */
	/* The last entry is the client binary */
	mybinary = &fresh_pinfo[fresh_pent - 1];
	pstmt = pica_find_policy(&ppol, mybinary);
	if (pstmt == NULL) {
	    printf("policy file is %s\n", pol_path); goto err_exit;
	}
	/*
	 * 1) Invocation Chain Verification
	 *    Verify the integrity of all binaries, including shared libraries
	 */
	verified |= pica_verify_binaries(fresh_pinfo, fresh_pent);
	/*
	 * 2) Invocation Chain Verification
	 *    Checking acceptable binaries listed in the policy statement.
	 */
	verified |= pica_check_ichain(pstmt, fresh_pinfo, fresh_pent);
	/*
	 * 3) Checking UIDs
	 */
	verified |= pica_check_uids(pstmt, fresh_pinfo, fresh_pent);	
	printf("Verification Results: Freshness %s, TPM2_Quote %s, "
	       "Binaries %s, Chain %s, UIDs %s\n",
	       (verified & VERIFY_TPM2_FRESH) ? "Verified" : "Failed",
	       (verified & VERIFY_TPM2_QUOTE) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_BINARIES) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_CHAIN) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_UIDS) ? "Verified" : "Failed");
	if (VERIFIED_ALL(verified)) {
	    printf("All verifications are success\n");
	    pica_actions_show(pstmt);
	}
    }
    getclocktime(&et_sec, &et_nsec);
    {
	double lat = time_to_msec(st_sec, st_nsec, mt_sec, mt_nsec);
	printf("*********Conf and Policy Read******\n");
	printf("start sec:(%ld) nsec(%ld)\n", st_sec, st_nsec);
	printf("end sec(%ld) nsec(%ld)\n", mt_sec, mt_nsec);
	printf("latency(msec): %f\n", lat);
	printf("***********************************\n\n");
    }
    {
	double lat = time_to_msec(st_sec, st_nsec, et_sec, et_nsec);
	printf("**Conf and Policy Read and Verify**\n");
	printf("start sec:(%ld) nsec(%ld)\n", st_sec, st_nsec);
	printf("end sec(%ld) nsec(%ld)\n", et_sec, et_nsec);
	printf("latency(msec): %f\n", lat);
	printf("***********************************\n\n");
    }
    return SGX_SUCCESS;
err_exit:
    return -1;
}
