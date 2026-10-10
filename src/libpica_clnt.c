#include <string.h>
#include <cbor.h>
#include <json.h>
#include <murmur3.h>
#include "libpica_clnt.h"
#include "libpica_clnt_internal.h"
#include "tpmdaemon.h"
#include "libsock.h"
#include "libio.h"
#include "error_check.h"

/*#include <fcntl.h>*/
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_EXCL		00000200
#define O_TRUNC		00001000
#define O_APPEND	00002000
#define O_NONBLOCK	00004000
#define O_DSYNC		00010000
#define FASYNC		00020000
#define O_DIRECT	00040000

#define SHOW	VERBOSE(vflag&VERB_PICA_POLICY)

extern char *strdup(const char *s);

void
procinfo_show(struct procinfo *cpif, int proc_cnt)
{
    int	i;
    for (i = 0; i < proc_cnt; i++) {
	int	j;
	struct fdigest	*fdigp = cpif[i].libs;

	printf("[%d]\tpath: %s\n", i, cpif[i].path);
	printf("\truid: %d\n", cpif[i].ruid);
	hexdump(stdout, "\tdigest: ", cpif[i].digest, 32);
	printf("\tlibs: %d\n", cpif[i].count);

	for (j = 0; j < cpif[i].count; j++) {
	    printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
	    hexdump(stdout, "\t\t->digest: ", fdigp[j].digest, 32);
	}
    }
}

/*
 * Convert serialized configuration data to in-memory structure
 */
static int
build_conf(uint8_t *buf, struct procinfo **pinfop)
{
    struct confhead	head;
    struct procinfo	*cpif;
    struct fdigest	*fdp;
    char		*sbuf;
    int	i;

    memcpy(&head, buf, sizeof(struct confhead));
    cpif = (struct procinfo*) (buf + sizeof (struct confhead));
    fdp  = (struct fdigest*) (((uint8_t*) cpif)
			      + sizeof(struct procinfo)*head.proc_cnt);
    sbuf = (char*) (((uint8_t*)fdp) + sizeof(struct fdigest)*head.fdig_cnt);

    for (i = 0; i < head.proc_cnt; i++) {
	/* path */
	cpif[i].path = sbuf + cpif[i].spos;
	/* pointer to the fdigest struct */
	if (cpif[i].count > 0) {
	    cpif[i].libs = ((struct fdigest*)fdp) + cpif[i].fpos;
	}
    }
    /* path in fdigest */
    for (i = 0; i < head.fdig_cnt; i++) {
	fdp[i].path = sbuf + fdp[i].spos;
    }
    *pinfop = cpif;
    return head.proc_cnt;
}

static void
reg_config(const char *fname, struct procinfo *pinfo, int entries)
{
    int	fd;
    int	i, j, ret;
    size_t	ssz = 0, wsz;
    int		fdcnt = 0;
    uint64_t	spos = 0;
    char	*sbuf;
    struct fdigest	*fdp_dst;
    int	fpos = 0;
    struct confhead	head;
    struct procinfo	*cpif;

    fd = file_open(fname, O_CREAT|O_RDWR, 0640);
    if (fd < 0) {
	printf("Cannot write configuration file: %s\n", fname);
	abort();
    }

    cpif = malloc(sizeof(struct procinfo)*entries); /* FIXME: */
    memcpy(cpif, pinfo, sizeof(struct procinfo)*entries);

    /* calculate path string size and both fdigest and string sizes */
    ssz = 0; fdcnt = 0;
    for (i = 0; i < entries; i++) {
	if (!pinfo[i].path) break;
	ssz += strlen(pinfo[i].path) + 1; /* path string */
	fdcnt += pinfo[i].count; /* fdiest entries */
	for (j = 0; j < pinfo[i].count; j++) { /* fdigest path string */
	    ssz += strlen(pinfo[i].libs[j].path) + 1;
	}
    }
    //printf("%s: fdigest count = %d string size = %ld\n", __func__, fdcnt, ssz);
    /* out fdigest */
    fdp_dst = malloc(sizeof(struct fdigest)*fdcnt);
    memset(fdp_dst, 0, sizeof(struct fdigest)*fdcnt); fpos = 0;
    /* out string */
    sbuf = malloc(ssz); /* FIXME: */
    memset(sbuf, 0, ssz); spos = 0;
    /* copy and set offset */
    for (i = 0; i < entries; i++) {
	size_t	len;
	/* exec path is copied to the string buffer */
	if (!pinfo[i].path) break;
	len = strlen(pinfo[i].path);
	memcpy(&sbuf[spos], pinfo[i].path, len);
	cpif[i].spos = spos;
	spos += len + 1; /* string position is updated */
	/* fdiget */
	VERBOSE(VERB_PICA_CONF) {
	    printf("%s: [%d] path=%s\n", __func__, i, pinfo[i].path);
	    printf("%s: \tcpif[%d].count=%d\n", __func__, i, cpif[i].count);
	}
	if (cpif[i].count > 0) {
	    struct fdigest	*fdp_src = pinfo[i].libs;
	    cpif[i].fpos = fpos;
	    for (j = 0; j < cpif[i].count; j++, fpos++) {
		len = strlen(fdp_src[j].path);
		/* path is copied to the string buffer */
		memcpy(&sbuf[spos], fdp_src[j].path, len);
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
    /* now writting */
    WSIZE_CHECK(err, wsz, sizeof(struct confhead),
		file_write(fd, &head, sizeof(struct confhead)));
    WSIZE_CHECK(err, wsz, sizeof(struct procinfo)*entries,
		file_write(fd, cpif, sizeof(struct procinfo)*entries));
    WSIZE_CHECK(err, wsz, sizeof(struct fdigest)*fdcnt,
		file_write(fd, fdp_dst, sizeof(struct fdigest)*fdcnt));
    WSIZE_CHECK(err, wsz, ssz, file_write(fd, sbuf, ssz));
    SYSCALL(err, ret, file_close(fd), "Cannot close a file: %s\n", fname);
    /* memory free */
err:
    free(sbuf);
    free(cpif);
    free(fdp_dst);
    return;
}

/*
 * PICA Library for Client application 
 */
void
picapol_show(struct pica_policy *pp)
{
    int	i;
    if (!strcmp(pp->version, PICA_POLICY_V0_STRING)) {
	printf("Version: V0\n");
    } else if (!strcmp(pp->version, PICA_POLICY_V1_STRING)) {
	printf("Version: V1\n");
    } else {
	printf("Version: Unknown (%s)\n", pp->version);
    }
    for (i = 0; i < pp->entries; i++) {
	struct pica_stmt *stmt = &pp->stmt[i];
	int	j;
	printf("[%d]\n", i);
	printf("\tsid: %s\n", stmt->sid);
	printf("\teffect: %d\n", stmt->effect);
	printf("\tpath: %s\n", stmt->exec_path);
	printf("\tuid(%d): ", stmt->uid_cnt);
	for (j = 0; j < stmt->uid_cnt; j++) {
	    printf("%d, ", stmt->uid[j]);
	}
	printf("\n\tfunctions(%d): ", stmt->act_cnt);
	for (j = 0; j < stmt->act_cnt; j++) {
	    printf("%s, ", stmt->action[j]);
	}
	printf("\n\tinvocation chain array(%d):\n", stmt->ary_cnt);
	for (j = 0; j < stmt->ary_cnt; j++) {
	    int	k;
	    printf("\t\tinvocation chain(%d): [\n", stmt->iarray[j].ichn_cnt);
	    for (k = 0; k < stmt->iarray[j].ichn_cnt; k++) {
		printf("\t\t    %s\n", stmt->iarray[j].ichain[k]);
	    }
    	    printf("\t\t]\n");
	}
    }
}

/*
 * "Sid": "comment"
 */
static char *
parse_sid(struct json_object *obj)
{
    // printf("%s\n", __func__);
    if (!json_object_is_type(obj, json_type_string)) {
	return NULL;
    }
    SHOW printf("\tSid: %s\n", json_object_get_string(obj));
    return strdup(json_object_get_string(obj));
}

/*
 * "Effect": "Allow" or "Deny"
 */
static int
parse_effect(struct json_object *obj)
{
    const char	*cp; 
    int	pol = PICA_NONE;
    // printf("%s\n", __func__);
    if (!json_object_is_type(obj, json_type_string)) {
	goto err;
    }
    cp = json_object_get_string(obj);
    if (!strcmp("Allow", cp)) {
	pol = PICA_ALLOW;
    } else if (!strcmp("Deny", cp)) {
	pol = PICA_DENY;
    }
    SHOW printf("\tEffect: %s\n", cp);
err:
    return pol;
}

/*
 * "Resource": "enclave"
 */
static char	*
parse_resource(struct json_object *obj)
{
    //printf("%s\n", __func__);
    if (!json_object_is_type(obj, json_type_string)) {
	return NULL;
    }
    SHOW printf("\tResource: %s\n", json_object_get_string(obj));
    return strdup(json_object_get_string(obj));
}

/*
 * "Binary": "..."
 */
static char	*
parse_binary(struct json_object *obj)
{
    //printf("%s\n", __func__);
    if (!json_object_is_type(obj, json_type_string)) {
	fprintf(stderr, "Binary must be string\n");
	return NULL;
    }
    SHOW printf("\t\tBinary: %s\n", json_object_get_string(obj));
    return strdup(json_object_get_string(obj));
}

/*
 *  "Uid": [ 1000, 1001, 1002 ]
 */
static void
parse_uid(struct json_object *obj, struct pica_stmt *stmt)
{
    int i;
    if (!json_object_is_type(obj, json_type_array)) {
	fprintf(stderr, "Uid must be string\n");
	return;
    }
    stmt->uid_cnt = json_object_array_length(obj);
    stmt->uid = malloc(sizeof(int)*stmt->uid_cnt);
    SHOW printf("\t\tUid: ");
    for (i = 0; i < stmt->uid_cnt; i++) {
	struct json_object *item = json_object_array_get_idx(obj, i);
	SHOW printf("%d, ", json_object_get_int(item));
	stmt->uid[i] = json_object_get_int(item);
    }
    SHOW printf("\n");
}

/*
 * "Principal": { "Binary": ..., "Uid": ... }
 */
static void
parse_principal(struct json_object *obj, struct pica_stmt *stmt)
{
    struct json_object *attr;
    //printf("%s\n", __func__);
    SHOW printf("\tPrincipal:\n");
    if (!json_object_is_type(obj, json_type_object)) {
        fprintf(stderr, "Principal must be object\n");
        return;
    }
    if (json_object_object_get_ex(obj, "Binary", &attr)) {
	stmt->exec_path = parse_binary(attr);
    }
    if (json_object_object_get_ex(obj, "Uid", &attr)) {
	parse_uid(attr, stmt);
    }
}

/*
 * "Action": [ ... ]
 */
static void
parse_action(struct json_object *obj, struct pica_stmt *stmt)
{
    int i;
    //printf("%s\n", __func__);
    if (!json_object_is_type(obj, json_type_array)) {
        fprintf(stderr, "Action must be array\n");
        return;
    }
    SHOW printf("\tAction:");
    stmt->act_cnt = json_object_array_length(obj);
    stmt->action = malloc(sizeof(char*)*stmt->act_cnt);
    memset(stmt->action, 0, sizeof(char*)*stmt->act_cnt);
    for (i = 0; i < json_object_array_length(obj); i++) {
        struct json_object *val = json_object_array_get_idx(obj, i);
        if (!json_object_is_type(val, json_type_string))  continue;
        SHOW printf("%s, ", json_object_get_string(val));
	stmt->action[i] = strdup(json_object_get_string(val));
    }
    SHOW printf("\n");
}

/*
 * V0:	"InvocationChain": [ ... ]
 * V1:	"InvocationChain": [ [ ... ], [ ... ], [ ... ] ] 
 */
static void
parse_invchain(struct json_object *obj, struct pica_stmt *stmt, struct pica_policy *pp)
{
    int	i, j;
    if (!json_object_is_type(obj, json_type_array)) {
	fprintf(stderr, "Error \"InvocationChain\" element must be array\n");
	return;
    }
    if (!strcmp(pp->version, PICA_POLICY_V0_STRING)) {
	stmt->ary_cnt = 1;
	stmt->iarray = malloc(sizeof(struct inv_array));
	stmt->iarray[0].ichn_cnt = json_object_array_length(obj);
	stmt->iarray[0].ichain = malloc(sizeof(char*)*stmt->iarray[0].ichn_cnt);
	memset(stmt->iarray[0].ichain, 0, sizeof(char*)*stmt->iarray[0].ichn_cnt);
	SHOW printf("\tInvocationChain (%d):\n", stmt->iarray[0].ichn_cnt);
	for (i = 0; i < json_object_array_length(obj); i++) {
	    struct json_object *item = json_object_array_get_idx(obj, i);
	    if (!json_object_is_type(item, json_type_string)) {
		fprintf(stderr, "InvocationChain item must be string\n");
		continue;
	    }
	    SHOW printf("\t\t%s\n", json_object_get_string(item));
	    stmt->iarray[0].ichain[i] = strdup(json_object_get_string(item));
	}
    } else if (!strcmp(pp->version, PICA_POLICY_V1_STRING)) {
	stmt->ary_cnt = json_object_array_length(obj);
	stmt->iarray = malloc(sizeof(struct inv_array)*stmt->ary_cnt);
	for (i = 0; i < json_object_array_length(obj); i++) {
	    struct json_object *array = json_object_array_get_idx(obj, i);
	    stmt->iarray[i].ichn_cnt = json_object_array_length(array);
	    stmt->iarray[i].ichain = malloc(sizeof(char*)*stmt->iarray[i].ichn_cnt);
	    memset(stmt->iarray[i].ichain, 0, sizeof(char*)*stmt->iarray[i].ichn_cnt);
	    SHOW printf("\tInvocationChain (%d):\n", stmt->iarray[i].ichn_cnt);
	    if (!json_object_is_type(array, json_type_array)) {
		fprintf(stderr, "Error \"InvocationChain\" element must be array\n");
		return;
	    }
	    for (j = 0; j < json_object_array_length(array); j++) {
		struct json_object *item = json_object_array_get_idx(array, j);
		if (!json_object_is_type(item, json_type_string)) {
		    fprintf(stderr, "InvocationChain item must be string\n");
		    continue;
		}
		SHOW printf("\t\t%s\n", json_object_get_string(item));
		stmt->iarray[i].ichain[j] = strdup(json_object_get_string(item));
	    }
	}
    } else {
	fprintf(stderr, "%s: internal error\n", __func__);
	return;
    }
}

static void
json_statement(struct json_object *obj, struct pica_policy *pp)
{
    int	i;
    
    if (!json_object_is_type(obj, json_type_array)) {
	fprintf(stderr, "Error \"Statement\" element must be array\n");
	return;
    }
    // printf("len = %ld\n", json_object_array_length(obj));
    pp->entries = json_object_array_length(obj);
    pp->stmt = malloc(sizeof(struct pica_stmt) * pp->entries);
    for (i = 0; i < json_object_array_length(obj); i++) {
	struct json_object *item = json_object_array_get_idx(obj, i);
	struct json_object *attr;
	struct pica_stmt   *stmt = &pp->stmt[i];
	int	ok = 0;
	SHOW printf("[%d] stmt=%p\n", i, stmt);

	if (!json_object_is_type(item, json_type_object)) {
            fprintf(stderr, "Statement[%d] must be object\n", i);
            continue;
        }
	if (json_object_object_get_ex(item, "Sid", &attr)) {
	    stmt->sid = parse_sid(attr); ok = 1;
	}
	if (json_object_object_get_ex(item, "Effect", &attr)) {
	    stmt->effect = parse_effect(attr); ok = 1;
	}
	if (json_object_object_get_ex(item, "Resource", &attr)) {
	    char	*cp;
	    cp = parse_resource(attr); ok = 1;
	    if (strcmp(cp, "enclave")) {
		fprintf(stderr, "Resource must be \"enclave\"");
	    }
	    free(cp);
	}
	if (json_object_object_get_ex(item, "Principal", &attr)) {
	    parse_principal(attr, stmt); ok = 1;
	}
	if (json_object_object_get_ex(item, "Action", &attr)) {
	    parse_action(attr, stmt); ok = 1;
	}
	if (json_object_object_get_ex(item, "InvocationChain", &attr)) {
	    parse_invchain(attr, stmt, pp); ok = 1;
	}
	if (!ok) {
	    fprintf(stderr, "Statement[%d] contains uknown attribute\n", i);
	}
    }
}

static char	*
json_version(struct json_object *obj)
{
    const char	*str;
    if (!json_object_is_type(obj, json_type_string)) {
	fprintf(stderr, "Error \"Version\" element is not a string\n");
	return NULL;
    }
    SHOW printf("Version: %s\n", json_object_get_string(obj));
    str = json_object_get_string(obj);
    if (!strcmp(str, PICA_POLICY_V0_STRING)
	&& !strcmp(str, PICA_POLICY_V1_STRING)) {
	fprintf(stderr, "Unexpected PICA policy verion\n");
    }
    return strdup(json_object_get_string(obj));
}

static void
pica_json_parse(struct json_object * const obj, struct pica_policy *pp)
{
    json_object_object_foreach(obj, key, val) {
	if (!strcmp(key, "Version")) {
	    pp->version = json_version(val);
	} else if (!strcmp(key, "Statement")) {
	    json_statement(val, pp);
	}
    }
}

#define HTABLE_SZ	1024
static struct pica_htable	pica_htable[HTABLE_SZ];

static uint32_t
myhash(const char *cp)
{
    uint32_t	hash;
    uint32_t	seed = 0;
    MurmurHash3_x86_32(cp, strlen(cp), seed, &hash);
    hash = ((hash>>16) ^ (hash&0xffff)) % HTABLE_SZ;
    if (hash == 0) hash = 1;
    return hash;
}

static void
reg_hashtable(int which, void *addr, const char *path)
{
    uint32_t	hash = myhash(path);

    //printf("%s: path: %s hash=0x%x\n", __func__, path, hash);
    if (pica_htable[hash].hash == 0) {
	pica_htable[hash].hash = hash;
	pica_htable[hash].hentry.type = which;
	pica_htable[hash].hentry.path = path;
	pica_htable[hash].hentry.addr = addr;
    } else {
	if (pica_htable[hash].hentry.type == which
	    && !strcmp(pica_htable[hash].hentry.path, path)) {
	    /* the same entry, skipping */
	} else { /* conflict */
	    struct pica_hentry *ph = &pica_htable[hash].hentry;
	    while (ph->next) {
		ph = ph->next;
		if (ph->type == which
		    && !strcmp(ph->path, path)) {
		    /* the same entry, skipping */
		    goto skip;
		}
	    }
	    struct pica_hentry *nent = malloc(sizeof(struct pica_hentry));
	    memset(nent, 0, sizeof(struct pica_hentry));
	    nent->type = which;
	    nent->path = path;
	    nent->addr = addr;
	    ph->next = nent;
	}
    skip:
    }
}

static void *
find_hashtable(const char *path, int which)
{
    void	*addr = NULL;
    struct pica_hentry *ph;
    uint32_t	hash = myhash(path);

    if (pica_htable[hash].hash == 0) goto skip;
    for (ph = &pica_htable[hash].hentry; ph != 0; ph = ph->next) {
	if (ph->type == which
	    && !strcmp(ph->path, path)) {
	    addr = ph->addr;
	    goto skip;
	}
    }
skip:
    return addr;
}


void
pica_build_hashtable(struct procinfo *procinfo, int entries)
{
    int	i;
    struct procinfo	*pif = procinfo;
    memset(pica_htable, 0, sizeof(pica_htable));
    for (i = 0; i < entries; i++) {
	reg_hashtable(PICA_ENT_CONF_PROCINFO, &pif[i], pif[i].path);
    }
}


int
pica_verify_digest(struct procinfo *regpinfo, struct procinfo *freshpinfo)
{
    struct fdigest	*reg_dig = regpinfo->libs;
    int			reg_cnt =  regpinfo->count;
    struct fdigest	*fresh_dig = freshpinfo->libs;
    int			fresh_cnt =  freshpinfo->count;
    int	i;
    //printf("%s: reg_cnt(%d) fresh_cnt(%d)\n", __func__, reg_cnt, fresh_cnt);
    if (reg_cnt != fresh_cnt) {
	printf("%s: reg_cnt(%d) fresh_cnt(%d)\n", __func__, reg_cnt, fresh_cnt);
	return -1;
    }
    /* execution binary digest verification */
    if (memcmp(regpinfo->digest, freshpinfo->digest, 32)) {
	/* exec binary digest verification fails */
	printf("%s: exec binary digest mismatch\n", __func__);
	printf("\tregistered path: %s\n", regpinfo->path);
	hexdump(stdout, "\tregistered digest: ", regpinfo->digest, 32);
	printf("\tfresh path: %s\n", freshpinfo->path);
	hexdump(stdout, "\tfresh digest: ", freshpinfo->digest, 32);
	goto bad;
    }
    /* library digest verfication */
    /* the order of shared library is different */
    for (i = 0; i < fresh_cnt; i++) {
	int	j;
	for (j = 0; j < fresh_cnt; j++) {
	    if (!strcmp(fresh_dig[i].path, reg_dig[j].path)) {
		/* The same library name */
		if (memcmp(fresh_dig[i].digest, reg_dig[j].digest,  32)) {
		    /* different */
		    printf("%s: library digest mismatch: %s\n",
			   __func__, fresh_dig[i].path);
		    hexdump(stdout, "\tregistered digest: ", reg_dig[j].digest, 32);
		    hexdump(stdout, "\tfresh digest: ", fresh_dig[i].digest, 32);
		    goto bad;
		}
		goto match;
	    }
	}
    match:
    }
    return 0;
bad:
    return -1;
}

/*
 * Verify the integrity of all binaries, including shared libraries
 * along with the invocation execution path.
 */
int
pica_verify_binaries(struct procinfo *pinfo, int ent)
{
    struct procinfo *cnfpinfo;
    int	rc = VERIFY_PICA_BINARIES;
    int	i;

    VERBOSE(VERB_VRFY_DIGEST) printf("%s (ent=%d):\n", __func__, ent);
    if (!pinfo) return 0;
    for (i = 0; i < ent; i++) {
	cnfpinfo = find_hashtable(pinfo[i].path, PICA_ENT_CONF_PROCINFO);
	if (cnfpinfo) {
	    int	vc;
	    vc = pica_verify_digest(cnfpinfo, &pinfo[i]);
	    if (vc < 0) { /* library digest error */
		printf("\tFound and verification fails: %s\n", pinfo[i].path);
		rc = 0;
	    } else {
		VERBOSE(VERB_VRFY_DIGEST) printf("\tFound and verified: %s\n", pinfo[i].path);
	    }
	} else {
	    printf("\tNot Found: %s\n", pinfo[i].path);
	    rc = 0;
	}
    }
    return rc;
}

/*
 * pica_stmt: policy statement
 * procinfo:  measured process invocatin chain
 */
int
pica_check_ichain(struct pica_stmt *pstmt, struct procinfo *pinfo, int ent)
{
    int rc = VERIFY_PICA_CHAIN;
    int	i, j;

    VERBOSE(VERB_PICA_POLICY) printf("%s: proc chain count(%d) ary_cnt(%d)\n", __func__, ent, pstmt->ary_cnt);
    for (i = 0; i < pstmt->ary_cnt; i++) {
	int	ccount = pstmt->iarray[i].ichn_cnt;
	char	**chain = pstmt->iarray[i].ichain;
	VERBOSE(VERB_PICA_POLICY) printf("%s:  ccount(%d) ent(%d)\n", __func__, ccount, ent);
	for (j = 0; j < ent; j++) {
	    char	*cp = pinfo[j].path;
	    VERBOSE(VERB_PICA_POLICY) printf("%s: [%d] pchain(%s) polchain(%s): ", __func__, j, cp, chain[j]);
	    if (strcmp(cp, chain[j])) {
		/* different path, error */
		rc = 0;
		VERBOSE(VERB_PICA_POLICY) printf("Unmatched\n");
		goto ext;
	    }
	    VERBOSE(VERB_PICA_POLICY) printf("Matched\n");
	}
	/* all found */
	goto found;
ext:
    }
found:
    return rc;
}

static int
match_uid(int *ids, int count, int id)
{
    int	i;
    for (i = 0; i < count; i++) {
	if (ids[i] == id) {
	    return 1; /* matched */
	}
    }
    /* no match */
    return 0;
}

int
pica_check_uids(struct pica_stmt *pstmt, struct procinfo *pinfo, int ent)
{
    int	count = pstmt->uid_cnt;
    int	*uids = pstmt->uid;
    int rc = 0;
    int	i;

    for (i = 0; i < ent; i++) {
	if (!match_uid(uids, count, pinfo[i].ruid)) goto bad;
    }
    rc = VERIFY_PICA_UIDS;
bad:
    return rc;
}

void
pica_actions_show(struct pica_stmt *pstmt)
{
    int	i;
    if (pstmt == NULL) return;
    printf("Actions: ");
    for (i = 0; i < pstmt->act_cnt; i++) {
	printf("%s, ", pstmt->action[i]);
    }
    printf("\n");
}

struct pica_stmt *
pica_find_policy(struct pica_policy *ppol, struct procinfo *bin)
{
    int		i;
    for (i = 0; i < ppol->entries; i++) {
	if (!strcmp(ppol->stmt[i].exec_path, bin->path)) {
	    /* found */
	    goto found;
	}
    }
    printf("%s: Policy statment is not found for %s\n", __func__, bin->path);
    printf("We have policies for the following commands\n");
    for (i = 0; i < ppol->entries; i++) {
	printf("\t%s\n", ppol->stmt[i].exec_path);
    }
    return 0;
found:
    return &ppol->stmt[i];
}

/*
 * reading procinfo from conf file
 */
int
pica_read_config(const char *confpath, struct procinfo	**procinfo)
{
    size_t	sz, wsz;
    uint8_t	*buffer;
    int	fd;
    int	entries = 0;
    int	i;
	
    printf("!!!!!! configuration read !!!!!!\n");
    fd = file_size(confpath, &sz);
    if (fd < 0) {
	fprintf(stderr, "Cannot open file: %s\n", confpath);
	*procinfo = NULL; entries = 0; goto err;
    }
    buffer = malloc(sz);
    wsz = file_read_close(fd, buffer, sz);
    if (wsz < 0) {
	fprintf(stderr, "Read error: %s\n", confpath);
	*procinfo = NULL; entries = 0; goto err;
    }
    entries = build_conf(buffer, procinfo);
    VERBOSE(VERB_CONF) printf("\tentries = %d\n", entries);
    VERBOSE(VERB_CONF) procinfo_show(*procinfo, entries);
    /* the allocated memory area is used, do not free */
    for (i = 0; i < entries; i++) {
	reg_hashtable(PICA_ENT_CONF_PROCINFO,
		      &(*procinfo)[i], (*procinfo)[i].path);
    }
    /* DO not free buffer */
err:
    return entries;
}

/*
 * 
 */
int
pica_read_policy(const char *polpath, struct pica_policy *ppol)
{
    int		fd;
    size_t	sz, rsz;
    char	*buffer;
    struct json_tokener *tok;
    struct json_object *jobj;
    int	i, rc = 0;

    printf("!!!!!! policy read !!!!!!\n");
    if (ppol == NULL) {
	fprintf(stderr, "%s: ppol is NULL\n", __func__);
	return -1;
    }
    fd = file_size(polpath, &sz);
    if (fd < 0) {
	fprintf(stderr, "Cannot open policy file: %s\n", polpath);
	rc = -1; goto err;
    }
    buffer = malloc(sz);
    rsz = file_read_close(fd, (uint8_t*) buffer, sz);
    if (sz != rsz) {
	fprintf(stderr, "Cannot read all policies\n");
	rc = -1; goto err;
    }
    tok = json_tokener_new();
    if (!tok) {
	fprintf(stderr, "%s: Cannot create Json tokener (%s).\n",
		__func__, json_util_get_last_err());
	rc = -1; goto err;
    }
    jobj = json_tokener_parse_ex(tok, buffer, rsz);
    if (!jobj) {
	fprintf(stderr, "%s: Parse error (%s)\n", __func__, json_util_get_last_err());
	rc = -1; goto err;
    }
    pica_json_parse(jobj, ppol);
    free(buffer);
    VERBOSE(VERB_PICA_POLICY) picapol_show(ppol);
    for (i = 0; i < ppol->entries; i++) {
	struct pica_stmt *stmt = &ppol->stmt[i];
	reg_hashtable(PICA_ENT_CONF_POLICY, stmt, stmt->exec_path);
    }
err:
    return rc;
}

#ifdef SGXENV
/*
 * Enclave side:
 * The interface:
 *   ocall_pica_request_measure(nonce, measure, sizeof(measure), &msz, pdaemon_path)
 * is generated by the egx_edger8r EDL compiler
 */
#include "pica_t.h"
int
pica_request_measure(uint8_t *nonce, uint8_t *measure, size_t msz,
		     size_t *sz,   const char *dpath)
{
    int	rc;
    ocall_pica_request_measure(nonce, measure, msz, sz, dpath, &rc);
    return rc;
}
#else
/*
 * Host-side implementation for SGX Enclave.
 * In non-SGX-Enclave environments, use pica_request_measure().
 */
extern int pica_request_measure(uint8_t *nonce, uint8_t *measure, size_t msz,
				size_t *sz,   const char *dpath);
void
ocall_pica_request_measure(uint8_t *nonce, uint8_t *measure, size_t msz,
			   size_t *sz,   const char *dpath, int *ret)
{
    *ret = pica_request_measure(nonce, measure, msz, sz, dpath);
}

int
pica_request_measure(uint8_t *nonce, uint8_t *measure, size_t msz,
		     size_t *sz,  const char *dpath)
{
    int	con;
    int	rc = -1;
    struct tpmd_packet	head;
    uint8_t	packet[sizeof(head)+1024];

    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    fprintf(stderr, "$ Talking to Atester Daemon (%ld B) (%s) \n", msz, dpath);
    fprintf(stderr, "$     %s\n", __func__);
    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    con = sock_connect_daemon(dpath);
    if (con < 0) goto err;
    /*
     * Request Attest to daemon
     */
    head.cmd = TPMD_REQ_PICA; head.len = 32;
    memcpy(packet, &head, sizeof(head));
    memcpy(&packet[sizeof(head)], nonce, 32);
    VERBOSE(VERB_PICA_DAEMON) {
	fprintf(stderr, "sending request attest packet-len=%ld data-len=%d\n",
		sizeof(packet),
		((struct tpmd_packet*)packet)->len);
    }
    rc = sock_send(con, packet, sizeof(struct tpmd_packet) + 32);
    if (rc < 0) goto err;
    /*
     * Receive Attest from daemon
     */
    rc = sock_recv(con, &head, sizeof(head));
    if (rc < 0) goto err;
    if (head.len > msz) {
	fprintf(stderr, "%s: buffer must be enlarged (%d), current(%ld)\n",
		__func__, head.len, msz);
	goto err;
    }
    rc = sock_recv(con, measure, head.len);
    if (rc < 0) goto err;
    *sz = head.len;
    return rc;
err:
    fprintf(stderr, "%s: ABORT !!!\n", __func__);
    return rc;
}
#endif

static void
tss_error(const char *cmd, TSS2_RC rc)
{
    const char	*message = Tss2_RC_Decode(rc);
    fprintf(stderr, "%s failed: 0x%x (%s)\n",  cmd, rc,
	    (message == NULL) ? "unknown TSS2 error" : message);
}

static cbor_item_t *
unpack_sercbor(cbor_item_t *item)
{
    unsigned char *cp;
    size_t	sz;
    cbor_item_t	*cbor = NULL;
    struct cbor_load_result res;

    if (cbor_typeof(item) != CBOR_TYPE_BYTESTRING) {
	fprintf(stderr, "%s: data is not a serialized CBOR(%d)\n",
	       __func__, cbor_typeof(item));
	goto err;
    }
    cp = cbor_bytestring_handle(item);
    sz = cbor_bytestring_length(item);
    cbor = cbor_load(cp, sz, &res);
    if (res.error.code != CBOR_ERR_NONE) {
	fprintf(stderr, "%s: data (size=%ld) is corruted (%d)\n", __func__, sz, res.error.code);
	cbor = NULL;
    }
err:
    return cbor;
}

static uint64_t
mycbor_get_int(cbor_item_t *val)
{
    uint64_t	ival;
    if (!cbor_isa_uint(val)) {
	fprintf(stderr, "%s: internal error\n", __func__);
	return -1;
    }
    ival = cbor_get_int(val);
    return ival;
}

static char	*
mycbor_get_string(cbor_item_t *val)
{
    char		*out;
    unsigned char	*str;
    size_t		len;

    if (!cbor_isa_string(val)) {
	fprintf(stderr, "%s: internal error\n", __func__);
	return NULL;
    }
    len = cbor_string_length(val);
    str = cbor_string_handle(val);
    out = malloc(len + 1);	// FIXME: check code
    strncpy(out, (char*) str, len);
    out[len] = 0;
    return out;
}

static int
mycbor_copy_bstring(uint8_t *out, cbor_item_t *val, size_t size)
{
    unsigned char	*bstr;
    size_t		bsz;
    if (!cbor_isa_bytestring(val)) {
	fprintf(stderr, "%s: internal error: not byte string\n", __func__);
	return -1;
    }
    bstr = cbor_bytestring_handle(val);
    bsz = cbor_bytestring_length(val);
    if (bsz != size) {
	fprintf(stderr, "%s: internal error: length(%ld)\n", __func__, bsz);
	return -1;
    }
    memcpy(out, bstr, bsz);
    return 0;
}

static int
tpm_ecdsa_to_der(const TPMS_SIGNATURE_ECDSA *tpm_sig,
                 unsigned char *der,  int *der_len)
{
    ECDSA_SIG	*sig = NULL;
    BIGNUM	*r = NULL;
    BIGNUM	*s = NULL;
    unsigned char *tmp;
    int	trc, rc = -1;
    int	len;

    CRYPT_CALL(err, r,
	       BN_bin2bn(tpm_sig->signatureR.buffer, tpm_sig->signatureR.size, NULL));
    CRYPT_CALL(err, s,
	       BN_bin2bn(tpm_sig->signatureS.buffer, tpm_sig->signatureS.size, NULL));
    CRYPT_CALL(err, sig, ECDSA_SIG_new());
    SSL_CALL(err, trc, ECDSA_SIG_set0(sig, r, s));
    /* query required size */
    len = i2d_ECDSA_SIG(sig, NULL);
    if (len <= 0) {
        goto err;
    }
    if (len > *der_len) {
	fprintf(stderr, "%s: ecdsa_der requires %d byte, but %d\n", __func__, len, *der_len);
	goto err;
    }
    tmp = der;
    if (i2d_ECDSA_SIG(sig, &tmp) != len) {
        goto err;
    }
    *der_len = len;
    rc = 0;
err:
    if (r) BN_free(r);
    if (s) BN_free(s);
    if (sig) ECDSA_SIG_free(sig);
    return rc;
}

/*
 * Checking PCR registers
 */
static int
check_tpm2pcrs(TPMS_ATTEST *tpm_atst, TPMS_ATTEST *reg_atst)
{
    int	rc = 0;
    TPMS_QUOTE_INFO	*qinfo_peer = &tpm_atst->attested.quote;
    TPMS_QUOTE_INFO	*qinfo_reg  = &reg_atst->attested.quote;

    VERBOSE(VERB_VRFY_TPM2Q) {
	show_tpm2quote_info("Registered", qinfo_reg);
    }
    rc = comp_pcr_selection(&qinfo_reg->pcrSelect, &qinfo_peer->pcrSelect);
    if (rc < 0) {
	fprintf(stderr, "%s: PCRregs are not identical\n", __func__);
    }
    return rc;
}

/*
 * extract tpm2 attastation data, TPMS_ATTEST
 */
static int
extract_tpm2attest(const uint8_t *s_quoted, int sq_size, TPMS_ATTEST *tpm_atst)
{
    size_t	off = 0;
    int	rc = -1;

    /* rc = 0 if success */
    TPM2_CALL(err, rc,
	      Tss2_MU_TPMS_ATTEST_Unmarshal(s_quoted, (size_t)sq_size,
					    &off, tpm_atst));
    if (tpm_atst->type != TPM2_ST_ATTEST_QUOTE) {
	fprintf(stderr, "%s: Data from Attester Daemon is not a TPM2 quote\n", __func__);
	goto err;
    }
    rc = 0;
err:
    return rc;
}

/*
 * verify_tpm2quote_sig returns
 *	0 : Verify Success
 *	-1: Verify Failed
 */
static int
verify_tpm2quote_sig(const uint8_t *s_quoted, int sq_size,
		     const TPMT_SIGNATURE *sig, EVP_PKEY *ak_pubkey)
{
    TPMI_ALG_HASH	hash_alg;
    const EVP_MD	*md;
    EVP_MD_CTX		*mdctx = NULL;
    EVP_PKEY_CTX	*pkey_ctx = NULL;
    const unsigned char *sig_data = NULL;
    size_t sig_size = 0;
    unsigned char	ecdsa_der[1024];
    int			ecdsa_der_size = sizeof(ecdsa_der);
    TSS2_RC trc;
    int ret, rc = -1;

    switch (sig->sigAlg) {
    case TPM2_ALG_RSASSA:
        hash_alg = sig->signature.rsassa.hash;
        sig_data = sig->signature.rsassa.sig.buffer;
        sig_size = sig->signature.rsassa.sig.size;
        break;
    case TPM2_ALG_RSAPSS:
        hash_alg = sig->signature.rsapss.hash;
        sig_data = sig->signature.rsapss.sig.buffer;
        sig_size = sig->signature.rsapss.sig.size;
        break;
    case TPM2_ALG_ECDSA:
        hash_alg = sig->signature.ecdsa.hash;
        if (tpm_ecdsa_to_der(&sig->signature.ecdsa, ecdsa_der,
			     &ecdsa_der_size) != 0) {
            fprintf(stderr, "ECDSA signature conversion failed\n");
	    goto err;
        }
        sig_data = ecdsa_der;
        sig_size = ecdsa_der_size;
        break;
    default:
        fprintf(stderr, "%s: Unsupported signature algorithm: 0x%04x\n",
		__func__, sig->sigAlg);
	goto err;
    }
    switch (hash_alg) {
    case TPM2_ALG_SHA1:   md = EVP_sha1(); break;
    case TPM2_ALG_SHA256: md = EVP_sha256(); break;
    case TPM2_ALG_SHA384: md = EVP_sha384(); break;
    case TPM2_ALG_SHA512: md = EVP_sha512();break;
    default:
	fprintf(stderr, "%s: Unsupported hash algorithm: 0x%04x\n",
		__func__, hash_alg);
	goto err;
    }

    SSL_CALLP(err, mdctx, EVP_MD_CTX_new());
    SSL_CALL(err, ret, EVP_DigestVerifyInit(mdctx, &pkey_ctx,
					    md, NULL, ak_pubkey));
    if (sig->sigAlg == TPM2_ALG_RSASSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
            fprintf(stderr, "%s: EVP_PKEY_CTX_set_rsa_padding error\n", __func__);
            goto err;
        }
    } else if (sig->sigAlg == TPM2_ALG_RSAPSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
	    fprintf(stderr, "%s: EVP_PKEY_CTX_set_rsa_padding error\n", __func__);
	    goto err;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md) <= 0) {
	    fprintf(stderr, "%s: EVP_PKEY_CTX_set_rsa_mgf1_md error\n", __func__);
	    goto err;
        }
    }
    if (EVP_DigestVerifyUpdate(mdctx, s_quoted, sq_size) != 1) {
	fprintf(stderr, "%s: EVP_DigestVerifyUpdate error\n", __func__);
        goto err;
    }
    trc = EVP_DigestVerifyFinal(mdctx, sig_data, sig_size);
    if (trc == 1) {
	VERBOSE(VERB_VRFY_TPM2Q) {
	    fprintf(stderr, "TPM2 Quote signature: VALID\n");
	}
	rc = 0;
    } else { /* error */
	if (trc == 0) {
	    VERBOSE(VERB_VRFY_TPM2Q) fprintf(stderr, "TPM2 Quote signature: INVALID\n");
	} else {
	    VERBOSE(VERB_VRFY_TPM2Q) fprintf(stderr, "OpenSSL signature verification error\n");
	}
    }
err:
    EVP_MD_CTX_free(mdctx);
    return rc;
}

/*****************************************************************************
 * TPM2 quote
 *      cbor map: "quote", "sign", "app-hash"
 *		the value of "app-hash" is copied to qdate
 *		udata is copied at verify_tpm2_quote()
 *			i.e., the value of tpm_atst.extraData.buffer
 *****************************************************************************/
/*
 * extract_tpm2quote_bundle:
 *	[in] item: cbor data containging TPM2 quote
 *	[out] quote: value of "quote", must be free by caller
 *	[out] q_sz: its size
 *	[out] apphath: value of "app-hash", 32 byte
 *	[out] tpm2_sig: TPM2 signature
 */
static int
extract_tpm2evidence_bundle(cbor_item_t *item,
			    uint8_t **quote, size_t *q_sz,
			    uint8_t *apphash, TPMT_SIGNATURE *tpm_sig)
{
    cbor_item_t		*cmap;
    struct cbor_pair	*cpair;
    int	i, cnt;
    int	rc = 0;

    if (!item || !quote || !apphash || !tpm_sig) {
	fprintf(stderr, "%s: item(%p) quote(%p) apphash(%p) tpm_sig(%p)\n",
		__func__, item, quote, apphash, tpm_sig);
	return 0;
    }
    if ((cmap = unpack_sercbor(item)) == NULL
	|| !cbor_isa_map(cmap)) {
	goto err_ext;
    }
    cpair = cbor_map_handle(cmap);
    cnt = cbor_map_size(cmap);
    /*
     * cbor map: "quote", "sign", "app-hash"
     */
    for (i = 0; i < cnt; i++) {
	cbor_item_t	*key = cpair[i].key;
	cbor_item_t	*val = cpair[i].value;
	char	*cp = (char*) cbor_string_handle(key);
	size_t	clen = cbor_string_length(key);
	if (!(key && cbor_isa_string(key) && val)) {
	    goto err_ext;
	}
		if (!strncmp("quote", cp, clen)) {
	    const uint8_t	*s_quote = cbor_bytestring_handle(val);
	    int		s_siz = cbor_bytestring_length(val);
	    *quote = malloc(s_siz);
	    memcpy(*quote, s_quote, s_siz);
	    *q_sz = s_siz;
	    rc |= EXTRACT_TPM2_QUTE;
	} else if (!strncmp("sign", cp, clen)) {
	    uint8_t	*sig_body = cbor_bytestring_handle(val);
	    int		sig_size = cbor_bytestring_length(val);
	    size_t	off = 0;
	    int		trc;
	    trc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(sig_body, sig_size, &off,
						   tpm_sig);
	    if (trc != 0) {
		fprintf(stderr, "%s: Tss2_MU_TPMT_SIGNATURE_Unmarshal error\n",
			__func__);
	    }
	    rc |= EXTRACT_TPM2_SIGN;
	} else if (!strncmp("app-hash", cp, clen)) { /* picainfo | nonce */
	    uint8_t	*body = cbor_bytestring_handle(val);
	    int		bsz = cbor_bytestring_length(val);
	    if (bsz != 32) {
		fprintf(stderr, "%s: \"app-hash\" size = %d\n", __func__, bsz);
	    }
	    memcpy(apphash, body, bsz);
	    rc |= EXTRACT_TPM2_APHASH;
	} else {
	    fprintf(stderr, "%s: Unrecogized key: %.*s\n", __func__, (int) clen, cp);
	    goto err_ext;
	}
    }
    return rc;
err_ext:
    fprintf(stderr, "%s: data is corrupted\n", __func__);
    return 0;
}

/*
 *
 */
static int
extract_tpm2evidence(uint8_t *measure, size_t msz,
		     uint8_t **quote, size_t *q_sz,
		     uint8_t *apphash, TPMT_SIGNATURE *tpm_sig,
		     uint8_t **picabody, size_t *pica_sz)
{
    struct cbor_load_result crslt;
    cbor_item_t *cmap = NULL;
    struct cbor_pair *cpair = NULL;
    int	i;
    int	rc = 0;

    /* cbor map:  0: tpm2_quote, 1:pica measures */
    cmap = cbor_load((unsigned char*)measure, msz, &crslt);
    if (crslt.error.code != CBOR_ERR_NONE) {
	printf("%s: received data is corruted\n", __func__);
	goto err;
    }
    if (!cbor_isa_map(cmap)) {
	printf("%s: received data is not a map\n", __func__);
	goto err;
    }
    /* map size check */
    if (cbor_map_size(cmap) != 2) {
	fprintf(stderr, "%s: cbor map size is not 2\n", __func__);
        goto err;
    }
    cpair = cbor_map_handle(cmap);
    //printf("cbor_map_size = %d\n", cbor_map_size(cmap));
    for (i = 0; i < cbor_map_size(cmap); i++) {
	cbor_item_t	*key = cpair[i].key;
	cbor_item_t	*val = cpair[i].value;
	char	*cp = (char*) cbor_string_handle(key);
	size_t	clen = cbor_string_length(key);
	if (key && cbor_isa_string(key) && val) {
	    if (!strncmp("tpm2_quote", cp, clen)) {
		rc |= extract_tpm2evidence_bundle(val, quote, q_sz, apphash, tpm_sig);
	    } else if (!strncmp("pica", cp, clen)) {
		uint8_t	*bdy = cbor_bytestring_handle(val);
		size_t	sz = cbor_bytestring_length(val);
		*picabody = malloc(sz);
		memcpy(*picabody, bdy, sz);
		*pica_sz = sz;
	    } else {
		printf("%s: Something Wrong... key = %.*s\n", __func__, (int) clen, cp);
	    }
	} else {
	    fprintf(stderr, "%s: cbor_typeof(key) = %d\n", __func__, cbor_typeof(key));
	}
    }
err:
    return rc;
}

/*
 * chack_apphash(picabody, pica_sz, nonce, apphash, udata)
 * picahash := HASH ( HASH(picabody) || nonce)
 * udata    := tpm_atst.extraData.buffer is udata
 * apphash  := "app-hash" in claims
 */
static int
check_apphash(uint8_t *picabody, size_t pica_sz,
	      uint8_t *nonce, uint8_t *apphash, uint8_t *udata)
{
    uint8_t	hash[32], picahash[32];
    int	rc = -1;
    memset(hash, 0, sizeof(hash));
    SHA256(picabody, pica_sz, hash); /* hash <-- HASH(picabody) */
    /* picahash <- HASH(hash || nonce) */
    if ((rc = hash_extend_sha256(hash, nonce, picahash)) < 0) {
	fprintf(stderr, "%s: internal error\n", __func__); goto err_ext;
    }

    if (!memcmp(picahash, udata, 32) && !memcmp(apphash, picahash, 32)) {
	/* verified */
	rc = 0;
    }
err_ext:
    return rc;
}

int
pica_verify_tpm2all(uint8_t *measure, size_t msz, uint8_t *nonce,
		    uint8_t **o_picabody, size_t *o_pica_sz)
{
    uint8_t		*quote = NULL;
    size_t		q_sz = 0;
    uint8_t		apphash[32];
    TPMT_SIGNATURE	tpm_sig;
    TPMS_ATTEST	tpm_atst;
    TPMS_ATTEST	reg_atst;
    uint8_t		*picabody = NULL;
    size_t		pica_sz = 0;
    EVP_PKEY	*ak_pubkey = NULL;
    int	trc, rc = 0;

    rc = extract_tpm2evidence(measure, msz, &quote, &q_sz,
			      apphash, &tpm_sig, &picabody, &pica_sz);
    if (!IS_EXTRACT_TPM2_ALL(rc)) {
	fprintf(stderr, "%s: Cannot obtain all info from measurement\n", __func__);
	goto err_exit;
    }
    trc = read_pubkey("ak_pub.pem", &ak_pubkey);
    if (trc < 0) goto err_exit;

    /* verify TPM2 signature */
    trc = verify_tpm2quote_sig(quote, q_sz, &tpm_sig, ak_pubkey);
    if (trc < 0) {
	fprintf(stderr, "%s: quote signature verification fails.\n", __func__);
	goto err_exit;
    }
    /* freshness has been verified */
    rc = VERIFY_TPM2_FRESH;
    /* extract TPM2 attestation */
    trc = extract_tpm2attest(quote, q_sz, &tpm_atst);
    if (trc < 0) {
	fprintf(stderr, "%s: Cannot exract TPM2 attestation data.\n", __func__);
	goto err_exit;
    }
    /* read registered attestation */
    trc = read_tpm2attest("reg_quote.bin", &reg_atst);
    if (trc < 0) {
	fprintf(stderr, "%s: Cannot read reg_quote.bin\n", __func__);
	goto err_exit;
    }
    /* checking PCRs */
    trc = check_tpm2pcrs(&tpm_atst, &reg_atst);
    if (trc < 0) {
	fprintf(stderr, "%s: tpm2pcrs fails\n", __func__);
	goto err_exit;
    }
    trc = check_apphash(picabody, pica_sz, nonce, apphash,
		       tpm_atst.extraData.buffer);
    if (trc == 0) {
	rc |= VERIFY_TPM2_QUOTE;
    }
    if (o_picabody) {
	*o_picabody = picabody;
	*o_pica_sz = pica_sz;
    } else {
	free (picabody);
    }
err_exit:
    return rc;
}

/*
 * PICA
 */
static int
extract_procinfo(cbor_item_t *carray, struct procinfo **out)
{
    struct procinfo *pinfo = NULL;
    size_t	entries;
    int	i;
    
    if (!carray || !cbor_isa_array(carray)) {
	fprintf(stderr, "%s: received data is corruted\n", __func__);
	goto err;
    }
    entries = cbor_array_size(carray);
    pinfo = malloc(sizeof(struct procinfo)*entries);  // FIXME: error check
    memset(pinfo, 0, sizeof(struct procinfo)*entries);
    for (i = 0; i < entries; i++) {
	size_t	count;
	cbor_item_t	*item = cbor_array_get(carray, i);
	cbor_item_t	*cmap = unpack_sercbor(item);
	struct cbor_pair *cpair = cbor_map_handle(cmap);
	count = cbor_map_size(cmap);
	/* the first 10 entries */
	pinfo[i].pid  = mycbor_get_int(cpair[0].value); /* "pid" */
	pinfo[i].ppid = mycbor_get_int(cpair[1].value); /* "ppid" */
	pinfo[i].ruid = mycbor_get_int(cpair[2].value); /* "ruid" */
	pinfo[i].rgid = mycbor_get_int(cpair[3].value); /* "rgid" */
	pinfo[i].euid = mycbor_get_int(cpair[4].value); /* "euid" */
	pinfo[i].egid = mycbor_get_int(cpair[5].value); /* "egid" */
	pinfo[i].suid = mycbor_get_int(cpair[6].value); /* "suid" */
	pinfo[i].sgid = mycbor_get_int(cpair[7].value); /* "sgid" */
	pinfo[i].path = mycbor_get_string(cpair[8].value); /* "path" */
	mycbor_copy_bstring(pinfo[i].digest, cpair[9].value, 32); /* "sha256" */
	//printf("%s: count = %d\n", __func__, count);
	if (count > 10) {
	    int	j, k;
		pinfo[i].count = count - 10;
		pinfo[i].libs = malloc(sizeof(struct fdigest) * pinfo[i].count);
		for (j = 0, k = 10; k < count; j++, k++) {
		    pinfo[i].libs[j].path = mycbor_get_string(cpair[k].key);
		    //printf("\t%s\n", pinfo[i].libs[j].path);
		    mycbor_copy_bstring(pinfo[i].libs[j].digest,
					cpair[k].value, 32);
		}
	}
    }
    *out = pinfo;
    return entries;
err:
    return 0;
}

/*
 * Extraction
 */
int
pica_extract_pinfo(uint8_t *picabody, size_t pica_sz,
		   struct procinfo **o_pinfo)
{
    struct cbor_load_result res;
    struct procinfo	*pinfo;
    int	entries;
    cbor_item_t *cbor;

    *o_pinfo = NULL;
    cbor = cbor_load(picabody, pica_sz, &res);
    if (res.error.code != CBOR_ERR_NONE) {
	fprintf(stderr, "%s: data (size=%ld) is corruted (%d)\n",
		__func__, pica_sz, res.error.code);
	return -1;
    }
    entries = extract_procinfo(cbor, &pinfo);
    if (entries == 0) {
	fprintf(stderr, "%s: No process inforation.\n", __func__);
	return -1;
    }
    *o_pinfo = pinfo;
    return entries;
}
/*
 * Register configuration file
 */
int
pica_reg_config(const char *path, uint8_t *picabody, size_t pica_sz)
{
    struct procinfo	*pinfo;
    int	entries;

    entries = pica_extract_pinfo(picabody, pica_sz, &pinfo);
    if (entries == 0) {
	fprintf(stderr, "%s: No process inforation.\n", __func__);
	return -1;
    }
    reg_config(path, pinfo, entries);
    free_pinfo(pinfo, entries);
    return 0;
}

#ifdef TEST_LIBPICA
#endif /*TEST_LIBPICA*/
