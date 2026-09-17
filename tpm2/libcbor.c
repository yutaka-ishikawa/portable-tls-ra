#include <sys/types.h>
#include <limits.h>
#include <string.h>
#include <cbor.h>
#include "libmeasurement.h"
#include "libprocchain.h"
#include "libcbor.h"

int
mycbor_add_map_bstring(cbor_item_t *map,
		       const char *key, const uint8_t *val, size_t sz)
{
    cbor_item_t	*ckey = NULL;
    cbor_item_t	*cval = NULL;
    struct cbor_pair	mapent;
    int	rc = 0; /* false */

    CBORCALLP(err0, ckey, cbor_build_string(key));
    CBORCALLP(err1, cval, cbor_build_bytestring(val, sz));
    mapent.key = ckey;
    mapent.value = cval;
    /* return value is boolean */
    CBORCALL(err2, rc, cbor_map_add(map, mapent));
    rc = 1; /* true */
err2:
    cbor_decref(&cval);
err1:
    cbor_decref(&ckey);
err0:
    return rc;
}

int
mycbor_add_map_string(cbor_item_t *map, const char *key, const char *val)
{
    cbor_item_t	*ckey = NULL;
    cbor_item_t	*cval = NULL;
    struct cbor_pair	mapent;
    int	rc = 0; /* false */

    CBORCALLP(err0, ckey, cbor_build_string(key));
    CBORCALLP(err1, cval, cbor_build_string(val));
    mapent.key = ckey;
    mapent.value = cval;
    /* return value is boolean */
    CBORCALL(err2, rc, cbor_map_add(map, mapent));
    rc = 1; /* true */
err2:
    cbor_decref(&cval);
err1:
    cbor_decref(&ckey);
err0:
    return rc;
}

int
mycbor_add_map_uint64(cbor_item_t *map,  const char *key, uint64_t val)
{
    cbor_item_t	*ckey = NULL;
    cbor_item_t	*cval = NULL;
    struct cbor_pair	mapent;
    int	rc = 0; /* false */

    CBORCALLP(err0, ckey, cbor_build_string(key));
    CBORCALLP(err1, cval, cbor_build_uint64(val));
    mapent.key = ckey;
    mapent.value = cval;
    /* return value is boolean */
    CBORCALL(err2, rc, cbor_map_add(map, mapent));
    rc = 1; /* true */
err2:
    cbor_decref(&cval);
err1:
    cbor_decref(&ckey);
err0:
    return rc;
}

cbor_item_t	*
mycbor_sha256_binaries(pid_t pid, pid_t *ppid)
{
    char		cmdpath[PATH_MAX+1];
    uint8_t		digest[64];
    unsigned int	dlen = sizeof(digest);
    struct path_entry	*paths = NULL, *pa;
    uid_t	ruid, rgid, euid, egid, suid, sgid;
    int		count, i;
    cbor_item_t	*cmap = NULL;


    /* cmdpath and sha256 of exec file */
    sha256_pid(pid, digest, &dlen, cmdpath, PATH_MAX+1);
    /* see man 5 proc_pid_status */
    cred_pid(pid, ppid, &ruid, &rgid, &euid, &egid, &suid, &sgid);
    /* sha256 of shared libraries */
    count = sha256_libs(pid, &paths);

    /* hash of libraries */
    CBORCALLP(err0, cmap, cbor_new_definite_map(count + PROCINFO_BASE_ENTRIES));
    mycbor_add_map_uint64(cmap, "pid", pid);
    mycbor_add_map_uint64(cmap, "ppid", *ppid);
    mycbor_add_map_uint64(cmap, "ruid", ruid);
    mycbor_add_map_uint64(cmap, "rgid", rgid);
    mycbor_add_map_uint64(cmap, "euid", euid);
    mycbor_add_map_uint64(cmap, "egid", egid);
    mycbor_add_map_uint64(cmap, "suid", suid);
    mycbor_add_map_uint64(cmap, "sgid", sgid);
    mycbor_add_map_string(cmap, "path", cmdpath);
    mycbor_add_map_bstring(cmap, "sha256", digest, 32);
    /* libraries hash */
    for (pa = paths, i = 0; i < count; i++) {
	mycbor_add_map_bstring(cmap, pa->path, pa->digest, 32);
	pa = pa->next;
    }
err0:
    return cmap;
}

uint8_t	*
mycbor_sha256_binaries_serial(pid_t pid, size_t *sz, pid_t *ppid)
{
    cbor_item_t	*map;
    uint8_t	*serial = NULL;
    map = mycbor_sha256_binaries(pid, ppid);
    if (map) {
	cbor_serialize_alloc(map, &serial, sz);
	if (*sz < 0) {
	    fprintf(stderr, "%s: Cannot serialization\n", __func__);
	}
	cbor_decref(&map);
    }
    return serial;
}

uint8_t	*
mycbor_pack_procchain(pid_t pid, size_t *size)
{
    struct tmplist {
	uint8_t		*ser;
	size_t		sz;
	pid_t		pid;
	struct tmplist	*next;
    };
    uint8_t	*outser = NULL;
    cbor_item_t	*array = NULL;
    pid_t	ppid;
    struct tmplist	*top = NULL;
    int	count = 0;

    do {
	size_t	sz;
	uint8_t	*serial = mycbor_sha256_binaries_serial(pid, &sz, &ppid);
	struct tmplist	*tl = malloc(sizeof(struct tmplist));
	tl->ser = serial; tl->sz = sz; tl->pid = pid; tl->next =NULL;
	if(!top) {
	    top = tl;
	} else { /* push */
	    tl->next = top; top = tl;
	}
	count++;
	pid = ppid;
    } while (pid != 1);
    printf("%s: count = %d\n", __func__, count);
    /* now making cbor */
    {
	int	rc;
	struct tmplist	*tl = top;
	CBORCALLP(err0, array, cbor_new_definite_array(count));
	while (tl) {
	    cbor_item_t	*pinfo;
	    CBORCALLP(err0, pinfo, cbor_build_bytestring(tl->ser, tl->sz));
	    CBORCALL(err0, rc, cbor_array_push(array, pinfo));
	    {
		struct tmplist	*t0;
		t0 = tl; tl = tl->next;
		free(t0);
	    }
	    cbor_decref(&pinfo);
	}
    }
    CBORCALL_SALLOC(err0, *size, cbor_serialize_alloc(array, &outser, size));
err0:
    if (array) cbor_decref(&array);
    return outser;
}

uint64_t
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

char	*
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

int
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

struct procinfo	*
mycbor_unpack_procchain(uint8_t *ser, size_t size, size_t *entries)
{
    struct procinfo *pinfo;
    cbor_item_t	*array;
    struct cbor_load_result	rslt;
    int	i;
    array = cbor_load(ser, size, &rslt);
    *entries = cbor_array_size(array);
    printf("%s: entries = %ld\n", __func__, *entries);
    pinfo = malloc(sizeof(struct procinfo)*(*entries+1));
    memset(pinfo, 0, sizeof(struct procinfo)*(*entries+1));
    for (i = 0; i < *entries; i++) {
	cbor_item_t	*item = cbor_array_get(array, i);
	unsigned char	*bstr = cbor_bytestring_handle(item);
	size_t		bsz = cbor_bytestring_length(item);
	cbor_item_t	*cmap = cbor_load(bstr, bsz, &rslt);
	if (cbor_isa_map(cmap)) {
	    size_t	count = cbor_map_size(cmap);
	    struct cbor_pair	*pp = cbor_map_handle(cmap);
	    /* 10 entries */
	    pinfo[i].pid  = mycbor_get_int(pp[0].value); /* "pid" */
	    pinfo[i].ppid = mycbor_get_int(pp[1].value); /* "ppid" */
	    pinfo[i].ruid = mycbor_get_int(pp[2].value); /* "ruid" */
	    pinfo[i].rgid = mycbor_get_int(pp[3].value); /* "rgid" */
	    pinfo[i].euid = mycbor_get_int(pp[4].value); /* "euid" */
	    pinfo[i].egid = mycbor_get_int(pp[5].value); /* "egid" */
	    pinfo[i].suid = mycbor_get_int(pp[6].value); /* "suid" */
	    pinfo[i].sgid = mycbor_get_int(pp[7].value); /* "sgid" */
	    pinfo[i].path = mycbor_get_string(pp[8].value); /* "path" */
	    mycbor_copy_bstring(pinfo[i].digest, pp[9].value, 32); /* "sha256" */
	    /* shared library digests */
	    if (count > 10) {
		int	j, k;
		pinfo[i].count = count - 10;
		pinfo[i].libs = malloc(sizeof(struct fdigest) * pinfo[i].count);
		for (j = 0, k = 10; k < count; j++, k++) {
		    pinfo[i].libs[j].path = mycbor_get_string(pp[k].key);
		    mycbor_copy_bstring(pinfo[i].libs[j].digest,
					pp[k].value, 32);
		}
	    } else { /* no shared library */
		pinfo[i].libs = NULL;
	    }
	} else {
	    printf("%s: Something wrong\n", __func__);
	}
    }
    return pinfo;
}

#ifdef LIBCBOR_TEST
#include <unistd.h>
static void
dump(FILE *fp, const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(fp, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(fp, "%02x:", bf[i]);
    }
    fprintf(fp, "\n");
}

int
main(int argc, char **argv)
{
    uint8_t	*serial;
    pid_t	pid = getpid();
    pid_t	ppid;
    size_t	sz;
    cbor_item_t	*cmap;
    struct cbor_load_result	rslt;
    struct cbor_pair		*pairs;
    int		count, i, rc = 0;

    /* serialized cbor */
    serial = mycbor_sha256_binaries_serial(pid, &sz, &ppid);
    /* deserialize */
    cmap = cbor_load(serial, sz, &rslt);
    if (cmap == NULL) {
	fprintf(stderr,
		"cbor_load failed: error=%d position=%zu\n",
		rslt.error.code, rslt.error.position);
	rc = -1;
    }
    pairs = cbor_map_handle(cmap);
    count = cbor_map_size(cmap);
    for (i = 0; i < count; i++) {
	unsigned char	*str = cbor_string_handle(pairs[i].key);
	int	len = cbor_string_length(pairs[i].key);
	
	if (cbor_typeof(pairs[i].value) == CBOR_TYPE_UINT) {
	    printf("key=%.*s, val=%ld\n", len, str,
		   cbor_get_uint64(pairs[i].value));
	} else if (cbor_typeof(pairs[i].value) == CBOR_TYPE_STRING) {
	    printf("key=%.*s, val=%.*s\n", len, str,
		   (int) cbor_string_length(pairs[i].value),
		   cbor_string_handle(pairs[i].value));
	} else if (cbor_typeof(pairs[i].value) == CBOR_TYPE_BYTESTRING) {
	    printf("key=%.*s, val=", len, str);
	    dump(stdout, "", cbor_bytestring_handle(pairs[i].value),
		 cbor_bytestring_length(pairs[i].value));
	} else {
	    printf("Not supported: cbor type = 0x%x", cbor_typeof(pairs[i].value));
	}
    }
    if (cmap) cbor_decref(&cmap);
    free(serial);

    /*
     * Checking procchain
     */
    {
	size_t	size;
	uint8_t	*ser;
	size_t	entries = 0;
	struct procinfo	*procinfo;
	ser = mycbor_pack_procchain(pid, &size);
	fprintf(stderr, "ser = %p size = %ld\n", ser, size);
	/* checking */
	procinfo = mycbor_unpack_procchain(ser, size, &entries);
	printf("Entries = %ld\n", entries);
	for (i = 0; i < entries; i++) {
	    printf("pid:%d ppid:%d ruid:%d euid:%d suid:%d %s\n",
		   procinfo[i].pid, procinfo[i].ppid,
		   procinfo[i].ruid, procinfo[i].euid, procinfo[i].suid,
		   procinfo[i].path);
	}
    }
    return rc;
}
#endif
