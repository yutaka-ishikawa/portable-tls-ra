/*
 * PICA conftool.
 *  Ex.
 *    - Display pica.conf
 *	$ conftool
 *	$ conftool -b
 *	$ conftool -d
 *	$ conftool -s
 *    - Measure command binary and its share libraries
 *	$ conftool -m /bin/bash
 *	$ conftool -m /usr/bin/emacs
 *
 *  Author: yutaka_ishikawa@me.com
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <murmur3.h>
#include <json-c/json.h>
#include "libutil.h"
#include "libpica_clnt.h"
#include "libmeasure.h"
#include "libio.h"
#include <sgx_urts.h>
#include "toollib_u.h"

#define SHOW_BINARY	1
#define SHOW_LIBS	2
#define SHOW_DIGEST	4
#define SHOW_UID	8
#define SHOW_ALL	(SHOW_BINARY|SHOW_LIBS|SHOW_DIGEST|SHOW_UID)
int	sflag = 0;
int	vflag = 0;
char	*afile = NULL;
char	*mfile = NULL;
char	*ppath = "./pica.conf";
#ifdef GETLIBS_CMD
char	*getlibs_path = GETLIBS_CMD;
#else
char	*getlibs_path = "./getlibs.sh";
#endif

#define ENCLAVE_CALL(label, val, lib, fmt, ...)	\
do {				\
    val = lib;			\
    if (val != SGX_SUCCESS) {	\
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	goto label;		\
    }				\
} while(0)

#define ENCLAVE_FILE "./toollib.signed.so"

static sgx_enclave_id_t	eid = 0;

static void
usage(const char *cmd)
{
    fprintf(stderr, "%s: [-f <config file>] [-a <command>] [-m <binary>] "
	    "[-s] [-l] [-h] [-c]\n", cmd);
    exit(-1);
}

/*
 * read_conf:
 *		struct procinfo * and entries
 *		struct fdigest * and entries
 *		char *sbuf, size
 */
static int
read_conf(char *path,
	  struct procinfo **o_cpif, int *o_proc_cnt,
	  struct fdigest  **o_fdp,  int *o_fdig_cnt,
	  char **o_sbuf, int *o_str_size)
{
    int	fd;
    sgx_status_t	st;
    uint8_t	*encdat, *decdat;
    uint32_t	dec_sz = -1;
    struct confhead	head;
    struct procinfo *cpif;
    struct fdigest  *fdp;
    char *sbuf;
    size_t		sz, rsz;
    int	proc_cnt, fdig_cnt, str_size;

    fd = file_size(path, &sz);
    if (fd < 0) {
	return -1;
    }
    encdat = malloc(sz); // FIXME: error check
    rsz = file_read_close(fd, encdat, sz);
    if (rsz != sz) {
	fprintf(stderr, "%s: Cannot read while file: %s\n", __func__, path);
	return -1;
    }
    decdat = malloc(rsz); // FIXME: error check
    ecall_unseal(eid, &st, rsz, encdat, rsz, decdat, &dec_sz);
    free(encdat);

    printf("decdata size = %d\n", dec_sz);
    memcpy(&head, decdat, sizeof(struct confhead));
    proc_cnt = head.proc_cnt; fdig_cnt = head.fdig_cnt; str_size = head.str_size;
    printf("\tprocinfo: %d entries\n", proc_cnt);
    printf("\tfdigest: %d entries\n", fdig_cnt);
    printf("\tstring buf: %d bytes\n", str_size);

    cpif = (struct procinfo *)(decdat + sizeof(struct confhead));
    fdp  = (struct fdigest *)(((uint8_t*)cpif) + sizeof(struct procinfo)*proc_cnt);
    sbuf = (char*) (((uint8_t*)fdp) + sizeof(struct fdigest)*fdig_cnt);
    { /* construct */
	int	i;
	for (i = 0; i < proc_cnt; i++) {
	    /* path */
	    cpif[i].path = sbuf + cpif[i].spos;
	    /* pointer to the fdigest struct */
	    if (cpif[i].count > 0) {
		cpif[i].libs = ((struct fdigest*)fdp) + cpif[i].fpos;
	    }
	}
	/* path in fdigest */
	for (i = 0; i < fdig_cnt; i++) {
	    fdp[i].path = sbuf + fdp[i].spos;
	}
    }
    *o_cpif = cpif; *o_proc_cnt = proc_cnt;
    *o_fdp = fdp; *o_fdig_cnt = fdig_cnt;
    *o_sbuf = sbuf; *o_str_size = str_size;
    return 0;
}


static void
show_conf(struct procinfo *cpif, int proc_cnt,
	  struct fdigest  *fdp,  int fdig_cnt,
	  char *sbuf, int str_size, int flg)
{
    int	i;
    for (i = 0; i < proc_cnt; i++) {
	int	j;
	char	buf[256];
	struct fdigest	*fdigp = cpif[i].libs;

	printf("[%d]\tpath: %s\n", i, cpif[i].path);
	if (flg & SHOW_UID) {
	    printf("\truid: %d\n", cpif[i].ruid);
	}
	if (flg & SHOW_DIGEST) {
	    hexdump(stdout, "\tdigest: ", cpif[i].digest, 32);
	}
	if (flg & SHOW_LIBS) {
	    printf("\tlibscount(%d)\n", cpif[i].count);
	    for (j = 0; j < cpif[i].count; j++) {
		printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
		if (flg & SHOW_DIGEST) {
		    printf("\tlibs[%d]->digest:", j); hexdump(stdout, "", fdigp[j].digest, 32);
		}
	    }
	}
    }
}

struct digest_list {
    char	*path;
    uint8_t	digest[32];
    uint32_t	dlen;
    int64_t	st_sec, st_nsec, et_sec, et_nsec;
    struct digest_list	*next;
};

static int
read_binary(const char *getlibs_cmd, const char *fname, struct digest_list *dlist)
{
    FILE *fp;
    struct stat sbuf;
    struct digest_list	*top = dlist;
    uint8_t	digest[32];
    uint32_t	dlen;
    char	dbuf[128], cmdbuf[128], linebuf[1024];
    int		count = 0;
    int rc;

    if (!dlist) return -1;
    /* command hash */
    dlist->path = strdup(fname);
    getclocktime(&dlist->st_sec, &dlist->st_nsec);
    rc = sha256_file(dlist->path, dlist->path, dlist->digest, &dlist->dlen);
    if (rc < 0) {
	return -1;
    }
    getclocktime(&dlist->et_sec, &dlist->et_nsec);

    /* checking if the getlibs_cmd file exists and executable o*/
    rc = stat(getlibs_cmd, &sbuf);
    if (rc < 0
	|| ((sbuf.st_mode & S_IFREG) != S_IFREG)
	|| ((sbuf.st_mode & 0100) != 0100)) {
	return -2;
    }
    
    /* libs hash */
    snprintf(cmdbuf, sizeof(cmdbuf), "%s %s", getlibs_cmd, fname);
    if ((fp = popen(cmdbuf, "r")) == NULL) {
	perror("popen");
	printf("%s: %d\n", __func__, __LINE__);
	return -1;
    }
    while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
	char	*cp = index(linebuf, '\n');
	int	rc;
	if (cp) *cp = 0;
	dlist->next = (struct digest_list*) malloc(sizeof(struct digest_list));
	memset(dlist->next, 0, sizeof(struct digest_list));
	dlist = dlist->next;
	dlist->path = strdup(linebuf);
	getclocktime(&dlist->st_sec, &dlist->st_nsec);
	rc = sha256_file(dlist->path, dlist->path, dlist->digest, &dlist->dlen);
	getclocktime(&dlist->et_sec, &dlist->et_nsec);
	if (rc < 0) {
	    printf("%s: cannot open\n", dlist->path);
	}
	count++;
    }
    pclose(fp);
    return count;
}

static int
append_conf(const char *afile)
{
    struct confhead	head;
    struct digest_list	dlist, *dlp;
    FILE	*fp;
    int	libs_cnt;
    struct procinfo *oinfo;
    struct procinfo *newpinfo, *pinfo, *cpif;
    struct fdigest  *fdp = NULL;
    struct fdigest  *fdp_dst;
    char	    *sbuf = NULL;
    int	proc_cnt, fdig_cnt, str_size;
    int	entries;
    int	fpos = 0;
    size_t		wsz;
    size_t	fdcnt, ssz, spos;
    int	rc, i, j;

    memset(&dlist, 0, sizeof(struct digest_list));
    libs_cnt = read_binary(getlibs_path, afile, &dlist);
    if (libs_cnt <= 0) return libs_cnt;
    printf("libs_cnt = %d\n", libs_cnt);

    rc = read_conf(ppath, &oinfo, &proc_cnt, &fdp, &fdig_cnt, &sbuf, &str_size);
    if (rc < 0) {
	/* create file */
    }
    printf("procinfo count: %d\n", proc_cnt);
    /* reconstruct procinfo*/
    entries = proc_cnt + 1; /* entries = +1 */
    newpinfo = malloc(sizeof(struct procinfo)*entries); /* FIXME: */
    memcpy(newpinfo, oinfo, sizeof(struct procinfo)*proc_cnt);
    pinfo = &newpinfo[proc_cnt];
    pinfo->pid = pinfo->ppid = 0;
    pinfo->ruid = pinfo->euid = pinfo->suid = getuid();
    pinfo->rgid = pinfo->egid = pinfo->sgid = getgid();
    pinfo->path = strdup(dlist.path);
    memcpy(pinfo->digest, dlist.digest, 32);
    pinfo->count = libs_cnt;
    pinfo->libs = (struct fdigest*) malloc(sizeof(struct fdigest) * libs_cnt);
    dlp = &dlist;
    for (i = 0; i < libs_cnt; i++) {
	dlp = dlp->next;
	if (!dlp) {
	    fprintf(stderr, "%s: internal error\n", __func__);
	    libs_cnt = 0;
	    goto ext;
	}
	pinfo->libs[i].path = strdup(dlp->path);
	printf("%s: libs[%d].path = %s\n", __func__, i, pinfo->libs[i].path);
	memcpy(pinfo->libs[i].digest, dlp->digest, 32);
    }
    /*
     * Now writting
     */
    fp = fopen(ppath, "w");
    if (fp == NULL) {
	rc = -1;
	goto ext;
    }
    cpif = malloc(sizeof(struct procinfo)*entries); /* FIXME: */
    memcpy(cpif, newpinfo, sizeof(struct procinfo)*entries);

    /* calculate path string size and both fdigest and string sizes */
    ssz = 0; fdcnt = 0;
    for (i = 0; i < entries; i++) {
	if (!newpinfo[i].path) break;
	ssz += strlen(newpinfo[i].path) + 1; /* path string */
	fdcnt += newpinfo[i].count; /* fdiest entries */
	for (j = 0; j < newpinfo[i].count; j++) { /* fdigest path string */
	    ssz += strlen(newpinfo[i].libs[j].path) + 1;
	}
    }
    //printf("%s: fdigest count = %d string size = %ld\n", __func__, fdcnt, ssz);
    /* out fdigest */
    fdp_dst = malloc(sizeof(struct fdigest)*fdcnt);
    memset(fdp_dst, 0, sizeof(struct fdigest)*fdcnt);
    fpos = 0;
    /* out string */
    sbuf = malloc(ssz); /* FIXME: */
    memset(sbuf, 0, ssz); spos = 0;
    /* copy and set offset */
    for (i = 0; i < entries; i++) {
	size_t	len;
	/* exec path is copied to the string buffer */
	if (!newpinfo[i].path) break;
	len = strlen(newpinfo[i].path);
	memcpy(&sbuf[spos], newpinfo[i].path, len + 1);
	cpif[i].spos = spos;
	spos += len + 1; /* string position is updated */
	/* fdiget */
	printf("%s: [%d] path=%s\n", __func__, i, newpinfo[i].path);
	printf("%s: \tcpif[%d].count=%d\n", __func__, i, cpif[i].count);
	if (cpif[i].count > 0) {
	    struct fdigest	*fdp_src = newpinfo[i].libs;
	    cpif[i].fpos = fpos;
	    printf("%s:\t   newpinfo[%d].libs = %p\n", __func__, i, fdp_src);
	    for (j = 0; j < cpif[i].count; j++, fpos++) {
		len = strlen(fdp_src[j].path);
		/* path is copied to the string buffer */
		printf("%s:\t\tspos(%ld) path(%s)\n", __func__, spos, fdp_src[j].path);
		memcpy(&sbuf[spos], fdp_src[j].path, len + 1);
		/* fdigest copied */
		fdp_dst[fpos].spos = spos; /* string position */
		memcpy(fdp_dst[fpos].digest, fdp_src[j].digest, 32);
		spos += len + 1; /* string buffer position is updated */
	    }
	}
    }
    //printf("fdcnt = %d fpos = %d strsize = %ld pos = %d\n", fdcnt, fpos, ssz, spos);
    /* prepare header */
    memset(&head, 0, sizeof(struct confhead));
    memcpy(head.magic, PROCCONF_MAGIC, sizeof(PROCCONF_MAGIC));
    head.proc_cnt = entries;
    head.fdig_cnt = fdcnt;
    head.str_size = ssz;
    wsz = fwrite(&head, sizeof(struct confhead), 1, fp); /* FIXME */
    wsz = fwrite(cpif, sizeof(struct procinfo)*entries, 1, fp); /* FIXME */
    wsz = fwrite(fdp_dst, sizeof(struct fdigest)*fdcnt, 1, fp); /* FIXME */
    wsz = fwrite(sbuf, ssz, 1, fp); /* FIXME */
    fclose(fp);
ext:
    return rc;
}

void
measure_bin(const char *getlibs_path, const char *file)
{
    struct digest_list	dlist, *dp;
    int	libs_cnt;
    float	msec, totmsec;

    memset(&dlist, 0, sizeof(struct digest_list));
    libs_cnt = read_binary(getlibs_path, file, &dlist);
    if (libs_cnt <= 0) {
	if (libs_cnt == -2) printf("The auxiliary command %s does not exist\n", getlibs_path);
	return;
    }
    dp = &dlist;
    totmsec = 0;
    while (dp) {
	msec = time_to_msec(dp->st_sec, dp->st_nsec, dp->et_sec, dp->et_nsec);
	printf("%s: ", dp->path);
	hexdump(stdout, "", dp->digest, dp->dlen);
	printf("\t: %f msec\n", msec);
	totmsec += msec;
	dp = dp->next;
    }
    printf("Total: %f msec\n", totmsec);
}

int
main(int argc, char **argv)
{
    sgx_launch_token_t	tok = {0};
    sgx_status_t	src;
    int		updated = 0;
    int	opt;
    struct procinfo *cpif = NULL;
    int	proc_cnt, fdig_cnt, str_size;

    while ((opt = getopt(argc, argv, "a:bc:df:suhm:")) != -1) {
	switch (opt) {
	case 'f':
	    ppath = optarg; break;
	case 'b': /* list binaries */
	    sflag |= SHOW_BINARY; break;
	case 'd': /* list digests */
	    sflag |= SHOW_DIGEST | SHOW_LIBS; break;
	case 'u': /* list uid */
	    sflag |= SHOW_UID | SHOW_LIBS; break;
	case 's': /* show all */
	    sflag = SHOW_ALL; break;
	case 'a': /* append */
	    afile = optarg;
	    break;
	case 'm': /* measure */
	    mfile = optarg;
	    break;
	case 'c': /* getlibs command path */
	    getlibs_path = optarg; break;
	case 'h':
	default:
	    usage(argv[0]);
	}
    }
    if(optind > argc) {
	usage(argv[0]);
    }
    if (mfile) {
	/* measure */
	measure_bin(getlibs_path, mfile);
	return 0;
    }
    ENCLAVE_CALL(err, src,
		 sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
				    &tok, &updated, &eid, NULL),
		 "sgx_create_enclave failed: 0x%x\n", src);

    if (afile) {
	fprintf(stderr, "-a option is not yet implemented\n");
	return 0;
	//append_conf(afile);
	return 0;
    }
    {  /* show configuration */
	struct fdigest  *fdp = NULL;
	char *sbuf = NULL;
	int	rc;
	printf("Configration file: %s\n", ppath);
	rc = read_conf(ppath, &cpif, &proc_cnt, &fdp, &fdig_cnt, &sbuf, &str_size);
	if (rc < 0) {
	    fprintf(stderr, "Cannot open %s\n", ppath);
	}
	show_conf(cpif, proc_cnt, fdp, fdig_cnt, sbuf, str_size, sflag);
    }
#if 0
    if(cpif && proc_cnt > 0) {
	pica_build_hashtable(cpif, proc_cnt);
    }
#endif
err:
    return 0;
}
