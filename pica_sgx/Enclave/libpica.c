#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <json.h>

#ifdef SGXENV
#include "sgxenv.h"
typedef int32_t pid_t;
typedef int32_t uid_t;
#endif
#include "pica.h"
#include "picatest.h"
#include "libpica.h"
#include "../../murmur3/murmur3.h"

#define SHOW	if (sflag)
int sflag = 0;
int ppol_ver = 0;

#ifdef SGXENV
static char *
strdup(const char *src)
{
    char *cp;
    size_t	len = strlen(src) + 1;
    cp = malloc(len);
    memcpy(cp, src, len);
    return cp;
}
#endif

void
picapol_show(struct pica_policy *pp)
{
    int	i;
    switch (ppol_ver) {
    case PICA_POLICY_V0:
	printf("Version: V0\n"); break;
    case PICA_POLICY_V1:
	printf("Version: V1\n"); break;
    default:
	printf("Version: Unknown (%s)\n", pp->version);
	return;
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
char *
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
int
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
char	*
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
char	*
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
void
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
void
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
void
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
void
parse_invchain(struct json_object *obj, struct pica_stmt *stmt)
{
    int	i, j;
    if (!json_object_is_type(obj, json_type_array)) {
	fprintf(stderr, "Error \"InvocationChain\" element must be array\n");
	return;
    }
    if (ppol_ver == PICA_POLICY_V0) {
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
    } else if (ppol_ver == PICA_POLICY_V1) {
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

void
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
	    parse_invchain(attr, stmt); ok = 1;
	}
	if (!ok) {
	    fprintf(stderr, "Statement[%d] contains uknown attribute\n", i);
	}
    }
}

char	*
json_version(struct json_object *obj)
{
    const char	*str;
    if (!json_object_is_type(obj, json_type_string)) {
	fprintf(stderr, "Error \"Version\" element is not a string\n");
	return NULL;
    }
    SHOW printf("Version: %s\n", json_object_get_string(obj));
    str = json_object_get_string(obj);
    if (!strcmp(str, PICA_POLICY_V0_STRING)) {
	ppol_ver = PICA_POLICY_V0;
    } else if (!strcmp(str, PICA_POLICY_V1_STRING)) {
	ppol_ver = PICA_POLICY_V1;
    } else {
	fprintf(stderr, "Unexpected PICA policy verion\n");
    }
    return strdup(json_object_get_string(obj));
}

void
json_parse(struct json_object * const obj, struct pica_policy *pp)
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

void
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

void *
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
build_hashtable(struct procinfo *procinfo, int entries)
{
    int	i;
    uint32_t	hash;
    struct procinfo	*pif = procinfo;
    memset(pica_htable, 0, sizeof(pica_htable));
    for (i = 0; i < entries; i++) {
	reg_hashtable(PICA_ENT_CONF_PROCINFO, &pif[i], pif[i].path);
    }
}

int
verify_digest(struct procinfo *regpinfo, struct procinfo *freshpinfo)
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
	dump("\tregistered digest: ", regpinfo->digest, 32);
	printf("\tfresh path: %s\n", freshpinfo->path);
	dump("\tfresh digest: ", freshpinfo->digest, 32);
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
		    dump("\tregistered digest: ", reg_dig[j].digest, 32);
		    dump("\tfresh digest: ", fresh_dig[i].digest, 32);
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
verify_binaries(struct procinfo *pinfo, int ent)
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
	    vc = verify_digest(cnfpinfo, &pinfo[i]);
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
check_ichain(struct pica_stmt *pstmt, struct procinfo *pinfo, int ent)
{
    int rc = VERIFY_PICA_CHAIN;
    int	i, j, k;

    printf("%s: proc chain count(%d) ary_cnt(%d)\n", __func__, ent, pstmt->ary_cnt);
    for (i = 0; i < pstmt->ary_cnt; i++) {
	int	ccount = pstmt->iarray[i].ichn_cnt;
	char	**chain = pstmt->iarray[i].ichain;
	printf("%s:  ccount(%d) ent(%d)\n", __func__, ccount, ent);
	for (j = 0; j < ent; j++) {
	    char	*cp = pinfo[j].path;
	    printf("%s: [%d] pchain(%s) polchain(%s)\n", __func__, j, cp, chain[j]);
	    if (strcmp(cp, chain[j])) {
		/* different path, error */
		rc = 0;
		goto ext;
	    }
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
check_uids(struct pica_stmt *pstmt, struct procinfo *pinfo, int ent)
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
show_actions(struct pica_stmt *pstmt)
{
    int	i;
    printf("Actions: ");
    for (i = 0; i < pstmt->act_cnt; i++) {
	printf("%s, ", pstmt->action[i]);
    }
    printf("\n");
}

struct pica_stmt *
find_policy(struct pica_policy *ppol, struct procinfo *bin)
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

#ifdef TEST_LIBPICA
#endif /*TEST_LIBPICA*/
