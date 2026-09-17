#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "Enclave/picatest.h"
#include "Enclave/libpica.h"
#include "../murmur3/murmur3.h"

char	*ppath = "./pica.conf";

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


int
main(int argc, char **argv)
{
    FILE	*fp;
    struct confhead	head;
    struct procinfo	*cpif;
    struct fdigest	*fdp;
    char		*sbuf;
    size_t		sz;
    int	proc_cnt, fdig_cnt, str_size;

    fp = fopen(ppath, "r");
    if (fp == NULL) {
	fprintf(stderr, "Cannot open %s\n", ppath);
	exit(-1);
    }
    sz = fread(&head, sizeof(struct confhead), 1, fp);
    proc_cnt = head.proc_cnt; fdig_cnt = head.fdig_cnt; str_size = head.str_size;
    printf("\tprocinfo: %d entries\n", proc_cnt);
    printf("\tfdigest: %d entries\n", fdig_cnt);
    printf("\tstring buf: %d bytes\n", str_size);

    cpif = malloc(sizeof(struct procinfo)*proc_cnt);
    fdp  = malloc(sizeof(struct fdigest)*fdig_cnt);
    sbuf = malloc(str_size);
    
    sz = fread(cpif, sizeof(struct procinfo), head.proc_cnt, fp);
    sz = fread(fdp, sizeof(struct fdigest), head.fdig_cnt, fp);
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

    { /* now checking */
	int	i;
	for (i = 0; i < proc_cnt; i++) {
	    int	j;
	    char	buf[256];
	    struct fdigest	*fdigp = cpif[i].libs;

	    printf("[%d]\tpath: %s\n", i, cpif[i].path);
	    printf("\truid: %d\n", cpif[i].ruid);
	    printf("\tdigest: %s\n", dump(cpif[i].digest, 32, buf, 256));

	    for (j = 0; j < cpif[i].count; j++) {
		printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
		printf("\tlibs[%d]->digest: %s\n", j,
		       dump(fdigp[j].digest, 32, buf, 256));
	    }
	}
    }
    build_hashtable(cpif, proc_cnt);
}
