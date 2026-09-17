#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>

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

#define SHOW	if (sflag)

int sflag = 0;


void
picapol_show(struct pica_policy *pp)
{
    int	i;
    printf("Version: %s\n", pp->version);
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
	printf("\n\tinvocation chain(%d):\n", stmt->ichn_cnt);
	for (j = 0; j < stmt->ichn_cnt; j++) {
	    printf("\t\t%s\n", stmt->ichain[j]);
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
 * "InvocationChain": [ ... ]
 */
void
parse_invchain(struct json_object *obj, struct pica_stmt *stmt)
{
    int	i;
    if (!json_object_is_type(obj, json_type_array)) {
	fprintf(stderr, "Error \"InvocationChain\" element must be array\n");
	return;
    }
    stmt->ichn_cnt = json_object_array_length(obj);
    stmt->ichain = malloc(sizeof(char*)*stmt->ichn_cnt);
    memset(stmt->ichain, 0, sizeof(char*)*stmt->ichn_cnt);
    SHOW printf("\tInvocationChain (%d):\n", stmt->ichn_cnt);
    for (i = 0; i < json_object_array_length(obj); i++) {
	struct json_object *item = json_object_array_get_idx(obj, i);
	if (!json_object_is_type(item, json_type_string)) {
	    fprintf(stderr, "InvocationChain item must be string\n");
	    continue;
	}
	SHOW printf("\t\t%s\n", json_object_get_string(item));
	stmt->ichain[i] = strdup(json_object_get_string(item));
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
    if (!json_object_is_type(obj, json_type_string)) {
	fprintf(stderr, "Error \"Version\" element is not a string\n");
	return NULL;
    }
    SHOW printf("Version: %s\n", json_object_get_string(obj));
    return strdup(json_object_get_string(obj));
}

void
json_parse(struct json_object* const obj, struct pica_policy *pp)
{
    json_object_object_foreach(obj, key, val) {
	if (!strcmp(key, "Version")) {
	    pp->version = json_version(val);
	} else if (!strcmp(key, "Statement")) {
	    json_statement(val, pp);
	}
    }
}

void
usage(const char *cmd)
{
    fprintf(stderr, "Usage:  %s [-s] <json-formatted policy file>\n", cmd);
    exit(-1);
}

int
main(int argc, char **argv)
{
    int	opt;
    struct json_object *jobj;

    if (argc == 1) usage(argv[0]);
    while ((opt = getopt(argc, argv, "s")) != -1) {
	switch (opt) {
	case 's':
	    sflag = 1;
	    break;
	}
    }
    if (optind >= argc) {
	fprintf(stderr, "Require json file\n");
	return -1;
    }
    jobj = json_object_from_file(argv[optind]);
    if (jobj == NULL) {
	fprintf(stderr, "Cannot open the json file: %s\n", argv[1]);
	return -1;
    }
    {
	struct pica_policy	ppol;
	json_parse(jobj, &ppol);
	json_object_put(jobj);
	picapol_show(&ppol);
    }
    return 0;
}
