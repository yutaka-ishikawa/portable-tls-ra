/*
 * This is a framework test code.
 * This main program runs inside TEE.
 */
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
struct timespec;
#include "Enclave_t.h"

#include <cbor.h>
#include <sgxenv.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include <tss2_tpm2_types.h>
#include <tss2_esys.h>
#include <tss2_mu.h>
#include <tss2_rc.h>
#include <tss2_tctildr.h>

#include <json.h>
#include "pica.h"
#include "libpica.h"
#include "picatest.h"

#define PICA_POLICY_PATH	"./policy.json"
#define PICA_CONF_PATH		"./pica.conf"
#define PICA_DAEMON_PATH	"/tmp/sock-tpmd-daemon"

int	dflag = 0;
int	vflag = 0;
int	rflag = 0;
char	*pol_path = PICA_POLICY_PATH;
char	*pconf_path = PICA_CONF_PATH;
char	*pdaemon_path = PICA_DAEMON_PATH;

static void
show_procinfo(struct procinfo *cpif, int proc_cnt)
{
    int	i;
    for (i = 0; i < proc_cnt; i++) {
	int	j;
	char	buf[256];
	struct fdigest	*fdigp = cpif[i].libs;

	printf("[%d]\tpath: %s\n", i, cpif[i].path);
	printf("\truid: %d\n", cpif[i].ruid);
	dump("\tdigest: ", cpif[i].digest, 32);

	for (j = 0; j < cpif[i].count; j++) {
	    printf("\tlibs[%d]->path: %s\n", j, fdigp[j].path);
	    dump("\t\t->digest: ", fdigp[j].digest, 32);
	}
    }
}


int
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

    ocall_open(fname, O_CREAT|O_RDWR, &fd);
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
    ocall_write(fd, &head, sizeof(struct confhead), &wsz); /* FIXME */
    ocall_write(fd, cpif, sizeof(struct procinfo)*entries, &wsz); /* FIXME */
    ocall_write(fd, fdp_dst, sizeof(struct fdigest)*fdcnt, &wsz); /* FIXME */
    ocall_write(fd, sbuf, ssz, &wsz); /* FIXME */
    ocall_close(fd, &ret);
    /* memory free */
    free(sbuf);
    free(cpif);
    free(fdp_dst);
err:
    return;
}


/*
 * Procinfo table is freed
 */
static void
free_pinfo(struct procinfo *pinfo, int entries)
{
    int	i, j;
    //printf("%s: pinfo[0].path = %p\n", __func__, pinfo[0].path);
    for (i = 0; i < entries; i++) {
	if (pinfo[i].path) free(pinfo[i].path);
	for (j = 0; j < pinfo[i].count; j++) {
	    printf("pinfo[%d].libs[%d].path = %p\n", i, j, pinfo[i].libs[j].path);
	    free(pinfo[i].libs[j].path);
	}
	free (pinfo[i].libs);
    }
    free(pinfo);
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
 * verify_tpm2_quote returns
 *	0 : Verify Success
 *	-1: Verify Failed
 */
static int
verify_tpm2_quote(const uint8_t *s_quoted, int sq_size,
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
            return -1;
        }
        sig_data = ecdsa_der;
        sig_size = ecdsa_der_size;
        break;
    default:
        fprintf(stderr, "%s: Unsupported signature algorithm: 0x%04x\n",
		__func__, sig->sigAlg);
        return -1;
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
	VERBOSE {
	    fprintf(stderr, "TPM2 Quote signature: VALID\n");
	}
	rc = 0;
    } else if (trc == 0) {
	VERBOSE {
	    fprintf(stderr, "TPM2 Quote signature: INVALID\n");
	}
    } else {
	fprintf(stderr, "OpenSSL signature verification error\n");
    }
err:
    EVP_MD_CTX_free(mdctx);
    return rc;
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

/*
 * TPM2 quote
 */
static int
handle_tpm2_quote(cbor_item_t *item)
{
    int	rc = 0;
    cbor_item_t	*cmap = unpack_sercbor(item);
    struct cbor_pair *cpair = cbor_map_handle(cmap);
    int	i;

    if (!cmap || !cbor_isa_map(cmap)) {
	fprintf(stderr, "%s: received data is corruted\n", __func__);
	rc = -1; goto err_ext;
    }
    if (cbor_map_size(cmap) != 3) {
	fprintf(stderr, "%s: cbor map size is not 3\n", __func__);
        goto err_ext;
    }
    {
	const uint8_t	*s_quote = NULL;
	int		s_siz = 0;
	TPMT_SIGNATURE	tpm_sig;
	EVP_PKEY *ak_pubkey = NULL;
	/*
	 * cbor map: "quote", "sign", "app-hash"
	 */
	for (i = 0; i < cbor_map_size(cmap); i++) {
	    cbor_item_t	*key = cpair[i].key;
	    cbor_item_t	*val = cpair[i].value;
	    char	*cp = (char*) cbor_string_handle(key);
	    size_t	clen = cbor_string_length(key);
	    if (!(key && cbor_isa_string(key) && val)) {
		fprintf(stderr, "%s: something wrong\n", __func__);
		continue;
	    }
	    if (!strncmp("quote", cp, clen)) {
		s_quote = cbor_bytestring_handle(val);
		s_siz = cbor_bytestring_length(val);
	    } else if (!strncmp("sign", cp, clen)) {
		uint8_t	*sig_body = cbor_bytestring_handle(val);
		int	sig_size = cbor_bytestring_length(val);
		size_t	off = 0;
		Tss2_MU_TPMT_SIGNATURE_Unmarshal(sig_body, sig_size, &off,
						 &tpm_sig);
	    } else if (!strncmp("app-hash", cp, clen)) {
	    }
	}
	if (s_quote) {
	    /* signature verification */
	    char	*fname = "ak_pub.pem";
	    void	*buf = NULL;
	    size_t	len = 0;
	    BIO		*bio = NULL;
	    EVP_PKEY	*ak_pubkey = NULL;

	    /* FIXME: here, this is ad-hoc code */
#define PEM_SIZE	(32*1024)
	    buf = malloc(PEM_SIZE);
	    ocall_readfile(fname, buf,  PEM_SIZE, &len);
	    if (len == 0) {
		goto err;
	    }
	    bio = BIO_new_mem_buf(buf, len);
	    ak_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	    if (ak_pubkey == NULL) {
		fprintf(stderr, "The %s file is not a PEM file.\n", fname);
		rc = -1; goto err;
	    }
	    rc = verify_tpm2_quote(s_quote, s_siz, &tpm_sig, ak_pubkey);
	    if (rc < 0) {
		VERBOSE fprintf(stderr, "%s: Verify Failed\n", __func__);
	    }
	    VERBOSE fprintf(stderr, "%s: verify success!\n", __func__);
	err:
	    if (buf) free(buf);
	    if (ak_pubkey) EVP_PKEY_free(ak_pubkey);
	} else {
	    fprintf(stderr, "%s: error!!!\n", __func__);
	}
    }
err_ext:
    return rc;
}


/*
 * PICA
 */
static int
handle_pica(cbor_item_t *item, struct procinfo **out)
{
    struct procinfo *pinfo = NULL;
    cbor_item_t	*carray = unpack_sercbor(item);
    size_t	entries;
    int	i, j;
    
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
	if (count > 10) {
	    int	j, k;
		pinfo[i].count = count - 10;
		pinfo[i].libs = malloc(sizeof(struct fdigest) * pinfo[i].count);
		for (j = 0, k = 10; k < count; j++, k++) {
		    pinfo[i].libs[j].path = mycbor_get_string(cpair[k].key);
		    printf("\t%s\n", pinfo[i].libs[j].path);
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

static void
usage(const char *cmd)
{
    fprintf(stderr, "%s: [-d] [-D <daemon path>] [-r <conf file>] [-p <policy file>]\n", cmd);
}

#define OPT_GET_STRVAL(dst, len, pos, argc, argv, lbl) \
do {						\
    if ((pos +1) >= argc) goto lbl;		\
    dst = strndup(argv[pos+1], len); pos++;	\
} while(0);
    
static int
getoption(int argc, char **argv)
{
    int	i;
    for (i = 1; i < argc; i++) {
	printf("argv[%d] = %s\n", i, argv[i]);
	if (argv[i][0] == '-') {
	    switch (argv[i][1]) {
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
	    case 'v':
		vflag = 1; printf("vflag is set\n"); break;
	    }
	} else {
	    break;
	}
    }
    return i;
err:
    usage(argv[0]);
    return -1;
}


int
main(int argc, char **argv)
{
    uint8_t	nonce[32];
    uint8_t	measure[1024*32];
    size_t	msz = sizeof(measure);
    sgx_status_t    sret;
    struct cbor_load_result crslt;
    cbor_item_t *cmap = NULL;
    cbor_item_t *item0 = NULL;
    cbor_item_t *item1 = NULL;
    struct procinfo	*fresh_pinfo = NULL;
    struct procinfo	*mybinary = NULL;
    int			fresh_pent = 0;
    struct pica_policy	ppol;
    struct pica_stmt	*pstmt;
    int		entries;
    int		verified = 0;
    int	i;
    int		rc = 0;

    DEBUG printf("%s: invoked\n", __func__);
    rc = getoption(argc, argv);
    if (rc < 0) {
	return -1;
    }
    if (rflag) { /* registering procinfo for configuration */
	printf("!!!!!! REGISTER MODE !!!!!!!\n");
    } else { /* reading procinfo from conf file */
	size_t	sz, wsz;
	uint8_t	*buffer;
	int	fd;
	int	entries;
	struct procinfo	*procinfo;
	
	printf("!!!!!! configuration read !!!!!!\n");
	ocall_pica_fsize(pconf_path, &sz, &fd);
	buffer = malloc(sz);
	ocall_pica_fread(fd, buffer, sz, &wsz);
	entries = build_conf(buffer, &procinfo);
	VERBOSE printf("\tentries = %d\n", entries);
	show_procinfo(procinfo, entries);
	/* the allocated memory area is used, do not free */
	for (i = 0; i < entries; i++) {
	    reg_hashtable(PICA_ENT_CONF_PROCINFO,
			  &procinfo[i], procinfo[i].path);
	}
    }
    {	/* policy read from file */
	size_t	sz, wsz;
	uint8_t	*buffer;
	int	fd;
	struct json_tokener *tok;
	struct json_object *jobj;

	printf("!!!!!! policy read !!!!!!\n");
	ocall_pica_fsize(pol_path, &sz, &fd);
	if (fd < 0) {
	    fprintf(stderr, "Cannot open policy file: %s\n", pol_path);
	    rc = -1;
	    goto err;
	}
	buffer = malloc(sz);
	ocall_pica_fread(fd, buffer, sz, &wsz);
	
	tok = json_tokener_new(); /* FIXME: */
	jobj = json_tokener_parse_ex(tok, buffer, wsz);
	if (!jobj) {
	    fprintf(stderr, "Error: %s\n", json_util_get_last_err());
	}
	json_parse(jobj, &ppol);
	free(buffer);
	VERBOSE picapol_show(&ppol);
	for (i = 0; i < ppol.entries; i++) {
	    struct pica_stmt *stmt = &ppol.stmt[i];
	    reg_hashtable(PICA_ENT_CONF_POLICY, stmt, stmt->exec_path);
	}
    }

    /**/
    sret = sgx_read_rand((unsigned char *)nonce, 32);
    if (sret != SGX_SUCCESS) {
        return -1;
    }
    memset(measure, 0, msz);
    printf("calling ocall_pica_measure with buf size = %ld Byte\n", msz);
    sret = ocall_pica_measure(nonce, measure, sizeof(measure), &msz, pdaemon_path);
    if (sret != SGX_SUCCESS) {
	printf("%s: ocall_pica_measure error sret=0x%x\n", __func__, sret);
	return -1;
    }
    printf("measure size = %ld Byte\n", msz);
    /*
     * cbor map:  0: tpm2_quote, 1:pica measures
     */
    cmap = cbor_load((unsigned char*)measure, msz, &crslt);
    if (crslt.error.code != CBOR_ERR_NONE) {
	printf("%s: received data is corruted\n", __func__);
	rc = -1; goto err;
    }
    if (!cbor_isa_map(cmap)) {
	printf("%s: received data is not a map\n", __func__);
	rc = -1; goto err;
    }
    /* map size check */
    if (cbor_map_size(cmap) != 2) {
	fprintf(stderr, "%s: cbor map size is not 2\n", __func__);
        goto err;
    }
    {
	struct cbor_pair *cpair = cbor_map_handle(cmap);
	int	i;

	//printf("cbor_map_size = %d\n", cbor_map_size(cmap));
	for (i = 0; i < cbor_map_size(cmap); i++) {
	    cbor_item_t	*key = cpair[i].key;
	    cbor_item_t	*val = cpair[i].value;
	    char	*cp = (char*) cbor_string_handle(key);
	    size_t	clen = cbor_string_length(key);
	    if (key && cbor_isa_string(key) && val) {
		if (!strncmp("tpm2_quote", cp, clen)) {
		    if (handle_tpm2_quote(val) == 0) {
			verified |= VERIFY_TPM2_QUOTE;
		    }
		} else if (!strncmp("pica", cp, clen)) {
		    int	entries;
		    struct procinfo *pinfo = NULL;
		    entries = handle_pica(val, &pinfo);
		    if (entries > 0 && rflag) {
			/* registration in configuration file */
			reg_config(pconf_path, pinfo, entries);
			free_pinfo(pinfo, entries);
		    } else {
			fresh_pinfo = pinfo; fresh_pent = entries;
		    }
		} else {
		    printf("%s: Something Wrong... key = %.*s\n", __func__, clen, cp);
		}
	    } else {
		printf("%s: cbor_typeof(key) = %d\n", __func__, clen, cbor_typeof(key));
	    }
	}
	if (rflag) goto ext;
	/* proc_fresh is generated from Attester Daemon */
	/* The last entry is the client binary */
	mybinary = &fresh_pinfo[fresh_pent - 1];
	printf("************* Now Verification for PICA ******************\n");
	// show_procinfo(mybinary, 1);
	/*
	 * 1) Invocation Chain Verification
	 *    Verify the integrity of all binaries, including shared libraries
	 */
	verified |= verify_binaries(fresh_pinfo, fresh_pent);
	/* Seaching a policy for mybinary */
	pstmt = find_policy(&ppol, mybinary);
	printf("Policy pstmt(%p)\n", pstmt);
	if (!pstmt) goto ext;
	printf("\teffect: %s\n",
	       pstmt->effect == PICA_ALLOW ? "allow" : "deny");
	{
	    int i;
	    printf("\tuid list:");
	    for (i = 0; i < pstmt->uid_cnt; i++) printf(" %d", pstmt->uid[i]);
	    printf("\n\taction list:");
	    for (i = 0; i < pstmt->act_cnt; i++) printf(" %s", pstmt->action[i]);
	    printf("\n\tinvocation chain:\n");
	    for (i = 0; i < pstmt->ichn_cnt; i++) {
		printf("\t\t%s\n", pstmt->ichain[i]);
	    }
	}
	/*
	 * 2) Invocation Chain Verification
	 *    Checking acceptable binaries listed in the policy statement.
	 */
	verified |= check_ichain(pstmt, fresh_pinfo, fresh_pent);
	/*
	 * 3) Checking UIDs
	 */
	verified |= check_uids(pstmt, fresh_pinfo, fresh_pent);
	/*
	 * All verification results:
	 */
	printf("Verification Results: TPM2_Quote %s, Binaries %s, Chain %s, UIDs %s\n",
	       (verified & VERIFY_TPM2_QUOTE) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_BINARIES) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_CHAIN) ? "Verified" : "Failed",
	       (verified & VERIFY_PICA_UIDS) ? "Verified" : "Failed");
	if (VERIFIED_ALL(verified)) {
	    show_actions(pstmt);
	}
    }
ext:
err:
    return rc;
}
