#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <json-c/json.h>
#include "Enclave/picatest.h"
#include "Enclave/libpica.h"
#include "../tpm2/libmeasurement.h"
#include "../murmur3/murmur3.h"

int	vflag = 0;
char	*afile = NULL;
char	*mfile = NULL;
char	*ppath = "./pica.conf";

static float
time_to_msec(int64_t st_sec, int64_t st_nsec, int64_t et_sec, int64_t et_nsec)
{
    int64_t sec = et_sec - st_sec;
    int64_t nsec = et_nsec - st_nsec;
    double msec;
    msec = (((double)sec*1000) + (double)(nsec)/(double)1000000);
    return (float) msec;
}

static void
getclocktime(int64_t *sec, int64_t *nsec)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
	perror("ocall_getclocktime");
	*sec = 0;
	*nsec = 0;
    } else {
	*sec  = (int64_t)ts.tv_sec;
	*nsec = (int64_t)ts.tv_nsec;
    }
}

char *
dump(uint8_t *digest, int size, char *buf, int bsz)
{
    int	i;
    int	off = 0;
    for (i = 0; i < size; i++) {
	int	cnt;
	off += sprintf(&buf[off], "%02x:", digest[i]);
	if ((off + 3) > bsz) goto err;
    }
    return buf;
err:
    fprintf(stderr, "%s: Not enough buffer is allocated\n", __func__);
    return buf;
}

static void
usage(const char *cmd)
{
    fprintf(stderr, "%s: [-f <config file>] [-a <command>] [-s] [-h]\n", cmd);
    exit(-1);
}

static int
read_conf(char *path,
	  struct procinfo **o_cpif, int *o_proc_cnt,
	  struct fdigest  **o_fdp,  int *o_fdig_cnt,
	  char **o_sbuf, int *o_str_size)
{
    FILE	*fp;
    struct confhead	head;
    struct procinfo *cpif;
    struct fdigest  *fdp;
    char *sbuf;
    size_t		sz;
    int	proc_cnt, fdig_cnt, str_size;

    fp = fopen(path, "r");
    if (fp == NULL) {
	return -1;
    }
    sz = fread(&head, sizeof(struct confhead), 1, fp);
    proc_cnt = head.proc_cnt; fdig_cnt = head.fdig_cnt; str_size = head.str_size;
    printf("\tprocinfo: %d entries\n", proc_cnt);
    printf("\tfdigest: %d entries\n", fdig_cnt);
    printf("\tstring buf: %d bytes\n", str_size);

    cpif = malloc(sizeof(struct procinfo)*proc_cnt);
    fdp  = malloc(sizeof(struct fdigest)*fdig_cnt);
    sbuf = malloc(str_size);

    /* procinfo */
    sz = fread(cpif, sizeof(struct procinfo), head.proc_cnt, fp);
    /* fdigest area */
    sz = fread(fdp, sizeof(struct fdigest), head.fdig_cnt, fp);
    /* string area */
    sz = fread(sbuf, 1, head.str_size, fp);
    fclose(fp);

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


void
show_conf(struct procinfo *cpif, int proc_cnt,
	  struct fdigest  *fdp,  int fdig_cnt,
	  char *sbuf, int str_size)
{
    int	i;
    for (i = 0; i < proc_cnt; i++) {
	int	j;
	char	buf[256];
	struct fdigest	*fdigp = cpif[i].libs;

	printf("[%d]\tpath: %s\n", i, cpif[i].path);
	printf("\truid: %d\n", cpif[i].ruid);
	printf("\tdigest: %s\n", dump(cpif[i].digest, 32, buf, 256));
	printf("\tlibscount(%d)\n", cpif[i].count);

	for (j = 0; j < cpif[i].count; j++) {
	    printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
	    printf("\tlibs[%d]->digest: %s\n", j,
		   dump(fdigp[j].digest, 32, buf, 256));
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
read_binary(const char *fname, struct digest_list *dlist)
{
    FILE *fp;
    struct digest_list	*top = dlist;
    uint8_t	digest[32];
    uint32_t	dlen;
    char	dbuf[128], cmdbuf[128], linebuf[1024];
    int		count = 0;

    if (!dlist) return -1;
    /* command hash */
    dlist->path = strdup(fname);
    getclocktime(&dlist->st_sec, &dlist->st_nsec);
    sha256_file(dlist->path, dlist->path, dlist->digest, &dlist->dlen);
    getclocktime(&dlist->et_sec, &dlist->et_nsec);
    dump(dlist->digest, dlist->dlen, dbuf, sizeof(dbuf));
    //printf("%s: %s\n", dlist->path, dbuf);

    /* libs hash */
    snprintf(cmdbuf, sizeof(cmdbuf), "./getlibs.sh %s", fname);
    if ((fp = popen(cmdbuf, "r")) == NULL) {
	perror("popen");
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
	if (rc == 0) {
	    dump(dlist->digest, dlist->dlen, dbuf, sizeof(dbuf));
	    //printf("%s: %s\n", dlist->path, dbuf);
	} else {
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
    libs_cnt = read_binary(afile, &dlist);
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
measure_bin()
{
    struct digest_list	dlist, *dp;
    int	libs_cnt;
    float	msec, totmsec;
    printf("measure bin file: %s\n", mfile);
    libs_cnt = read_binary(mfile, &dlist);
    dp = &dlist;
    totmsec = 0;
    while (dp) {
	msec = time_to_msec(dp->st_sec, dp->st_nsec, dp->et_sec, dp->et_nsec);
	printf("measure %s: %f msec\n", dp->path, msec);
	totmsec += msec;
	dp = dp->next;
    }
    printf("Total: %f msec\n", totmsec);
}

int
main(int argc, char **argv)
{
    int	opt;
    struct procinfo *cpif = NULL;
    int	proc_cnt, fdig_cnt, str_size;

    while ((opt = getopt(argc, argv, "f:sa:hm:")) != -1) {
	switch (opt) {
	case 'f':
	    ppath = optarg; break;
	case 's': /* show */
	    sflag = 1; break;
	case 'a': /* append */
	    afile = optarg;
	    break;
	case 'm': /* measure */
	    mfile = optarg;
	    break;
	case 'h':
	default:
	    usage(argv[0]);
	}
    }
    if(optind > argc) {
	usage(argv[0]);
    }

    if (mfile) {
	measure_bin();
	return 0;
    }
    if (sflag) {
	struct fdigest  *fdp = NULL;
	char *sbuf = NULL;
	int	rc;
	rc = read_conf(ppath, &cpif, &proc_cnt, &fdp, &fdig_cnt, &sbuf, &str_size);
	if (rc < 0) {
	    fprintf(stderr, "Cannot open %s\n", ppath);
	}
	show_conf(cpif, proc_cnt, fdp, fdig_cnt, sbuf, str_size);
    }
    if (afile) {
	append_conf(afile);
    }
    if(cpif && proc_cnt > 0) {
	build_hashtable(cpif, proc_cnt);
    }
    return 0;
}
