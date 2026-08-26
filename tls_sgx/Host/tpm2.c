/*
 * We assume that the format of the AK public key is PEM.
 *	$ openssl pkey -pubin -in ak_pub.pem -text -noout
 * AK: 0x81018001, TPM2_ALG_SHA256
 *  $ tpm2_createek -G rsa -c ek.ctx -u ek.pub
 *  $ tpm2_createak -C ek.ctx -G rsa -g sha256 -c ak.ctx -u ak.pub -n ak.name
 *  $ tpm2_evictcontrol -C o -c ak.ctx 0x81018001
 *  $ tpm2_readpublic -c ak.ctx -f pem -o ak_pub.pem
 *  $ tpm2_quote -c 0x81018001 -l sha256:0,1,2,7,10 -q nonce.bin \
 *		 -m quote.bin -s quote.sig			 \
 *		 -f plain --scheme rsassa -g sha256 -o pcrs.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "Enclave_u.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <cbor.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include "ptlsra.h"
#include "../../tpm2/libquote.h"
#include "../../tpm2/libmeasurement.h"
#include "../../tpm2/libsock.h"
#include "../../tpm2/tpmdaemon.h"

#ifndef VERBOSE
extern int	vflag;
#define VERBOSE	if (vflag)
#endif

#define TPM2_CALL(lbl, rc, command)	\
do {					\
    rc = command;			\
    if (rc != TSS2_RC_SUCCESS) {	\
	tss_error(#command, rc);	\
        goto lbl;			\
    }					\
} while(0)

static void
tss_error(const char *cmd, TSS2_RC rc)
{
    const char	*message = Tss2_RC_Decode(rc);
    fprintf(stderr, "%s failed: 0x%x (%s)\n",  cmd, rc,
	    (message == NULL) ? "unknown TSS2 error" : message);
}

static void
dump(const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(stderr, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(stderr, "%02x:", bf[i]);
    }
    fprintf(stderr, "\n");
}

int
myssl_printerr(const char *str, size_t len, void *u)
{
    char	*buf = NULL;
    TLSRA_LIBCALLPmsg(err, buf, malloc(len + 1),
		      "%s: Cannot allocate memory size(%ld)\n", __func__, len+1);
    strncpy(buf, str, len);
    buf[len] = 0;
    printf("SSLerror: %s\n", str);
    free(buf);
    return 1;
err:
    printf("%s: cannot allocate memory\n", __func__);
    return 1;
}


/*
 * return value is true (1) or false(0)
 */
static int
add_cbor_map(cbor_item_t *map, const char *key, const uint8_t *val, size_t sz)
{
    cbor_item_t	*ckey;
    cbor_item_t	*cval;
    struct cbor_pair	mapent;
    int	rc = 0; /* false */

    TLSRA_CBORCALLP(err0, ckey, cbor_build_string(key));
    TLSRA_CBORCALLP(err1, cval, cbor_build_bytestring(val, sz));
    mapent.key = ckey;
    mapent.value = cval;
    /* return value is boolean */
    TLSRA_CBORCALL(err2, rc, cbor_map_add(map, mapent));
    rc = 1; /* true */
err2:
    cbor_decref(&cval);
err1:
    cbor_decref(&ckey);
err0:
    return rc;
}

void
ocall_make_tpm2_quote_via_daemon(uint8_t *nonce, int nsize, size_t qbsize,
				 uint8_t *tpm2_serial, size_t *sz,
				 const char *dpath)
{
    int	con;
    int	rc;
    struct tpmd_packet	head;
    uint8_t	packet[sizeof(head)+32];
    uint8_t	buf[1024];

    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    fprintf(stderr, "$ Talking to Atester Daemon (%s)\n", dpath);
    fprintf(stderr, "$     %s\n", __func__);
    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

    con = sock_connect(dpath);
    if (con < 0) goto err;
    /*
     * Request Attest to daemon
     */
    head.cmd = TPMD_REQ_ATTEST; head.len = 32;
    memcpy(packet, &head, sizeof(head));
    memcpy(&packet[sizeof(head)], nonce, 32);
    VERBOSE {
	fprintf(stderr, "sending request attest packet-len=%ld data-len=%d\n",
		sizeof(packet),
		((struct tpmd_packet*)packet)->len);
    }
    rc = sock_send(con, packet, sizeof(packet));
    if (rc < 0) goto err;
    /*
     * Receive Attest from daemon
     */
    rc = sock_recv(con, &head, sizeof(head));
    if (rc < 0) goto err;
    //printf("head.cmd=0x%x head.len=%d qbsize=%ld\n", head.cmd, head.len, qbsize);
    if (sizeof(buf) < head.len) {
	fprintf(stderr, "%s: buf area must be enlarged (%ld, %d)\n",
		__func__, sizeof(buf), head.len);
	goto err;
    }
    rc = sock_recv(con, buf, head.len);
    /*
     * extracting data from Attester Daemon
     */
    {
	struct cbor_load_result	res;
	cbor_item_t	*cpkt = cbor_load(buf, head.len, &res);
	struct cbor_pair	*cpair;
	uint8_t		*rec_nonce = NULL;
	uint8_t		*s_quote = NULL;
	size_t		s_sz;
	int i;
	
	if (cpkt == NULL || cbor_typeof(cpkt) != CBOR_TYPE_MAP) {
	    fprintf(stderr, "%s: Received data is not a CBOR map\n", __func__);
	    goto err;
	}
	cpair = cbor_map_handle(cpkt);
	for (i = 0; i < cbor_map_size(cpkt); i++) {
	    cbor_item_t	*key = cpair[i].key;
	    char		*cp = (char*) cbor_string_handle(key);
	    size_t		clen = cbor_string_length(key);
	    if (!key || !cbor_isa_string(key)) continue;
	    if (!strncmp(cp, "nonce", clen)) {
		rec_nonce = cbor_bytestring_handle(cpair[i].value);
		/*
		 * Checking nonce
		 */
	    } else if (!strncmp(cp, "tpm2_quote", clen)) {
		s_quote = cbor_bytestring_handle(cpair[i].value);
		s_sz   = cbor_bytestring_length(cpair[i].value);
		//fprintf(stderr, "s_quote = %p, s_sz = %ld\n", s_quote, s_sz);
	    }
	}
	/* tpm2 quote is copied */
	if (qbsize < s_sz) {
	    fprintf(stderr, "%s: tpm2_serial area must be enlarged (%ld, %ld)\n",
		    __func__, qbsize, s_sz);
	    goto err;
	}
	memcpy(tpm2_serial, s_quote, s_sz);
	*sz = s_sz;
    }
    if (rc < 0) goto err;
    *sz = head.len;
    return;
err:
    fprintf(stderr, "%s: ABORT !!!\n", __func__);
    abort();
}

void
ocall_make_tpm2_quote(uint8_t *nonce, int nsize, size_t qbsize,
		      uint8_t *tpm2_serial, size_t *sz)
{
    uint8_t	*tpm2_qbuf = NULL;
    size_t	tpm2_qbsz = 0;
    uint8_t	apphash[32];
    uint8_t	newhash[32];
    unsigned int	usize = 32;
    int	alg = TPM2_ALG_SHA256;
    uint8_t	pcrs[] = {0, 1, 2, 7, 10};
    int	count = 5;
    int pid;
    int	rc;
    struct tpm2_quote	t_quote;
    cbor_item_t		*c_tpm2_quote = NULL;

    pid = getpid();
    VERBOSE {
	fprintf(stderr, "===================================================\n");
	fprintf(stderr, " Direct TPM2 Device Access (pid=%d)\n", pid);
	fprintf(stderr, "     %s\n", __func__);
	fprintf(stderr, "===================================================\n");
    }

    /* get self measurement */
    sha256_pid(pid, apphash, &usize);

    /* app-hash || nonce */
    rc = hash_extend_sha256(apphash, nonce, newhash);
    VERBOSE {
	dump("@@@@@@@ apphash: ", apphash, 32);
	dump("@@@@@@@ nonce: ", nonce, 32);
	dump("@@@@@@@ TPM2 EXTEND(app-hash || nonce): ", newhash, 32);
    }
    rc = make_tpm2_quote(newhash, nsize,
			 TPM2_ALG_SHA256, pcrs, count, 0x81018001,
			 &t_quote);
    if (rc < 0) {
	fprintf(stderr, "%s: make_tpm2_quote error\n", __func__);
	goto err0;
    }
    {
	size_t	off = 0;
	TPMS_ATTEST	tpm_atst;
	TPMS_QUOTE_INFO *qinfo;
	Tss2_MU_TPMS_ATTEST_Unmarshal(t_quote.quote, t_quote.qsize,
				      &off, &tpm_atst);
	if (tpm_atst.type != TPM2_ST_ATTEST_QUOTE) {
	    fprintf(stderr, "%s: TPM2 Quote is expected, but type = 0x%x\n",
		    __func__, tpm_atst.type);
	    goto err0;
	}
	qinfo = &tpm_atst.attested.quote;
	VERBOSE {
	    show_tpm2quote_info("My", qinfo);
	}
    }    
    TLSRA_CBORCALLP(err1, c_tpm2_quote, cbor_new_definite_map(3));
    /* cbor-map: quote */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "quote",
				t_quote.quote, t_quote.qsize));
    /* cbor-map: sign */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "sign",
				t_quote.sign, t_quote.ssize));
    /* app-hash */
    TLSRA_CBORCALL(err2, rc,
		   add_cbor_map(c_tpm2_quote, "app-hash", apphash, usize));
    cbor_serialize_alloc(c_tpm2_quote, &tpm2_qbuf, &tpm2_qbsz);
    if (tpm2_qbsz <= 0 || tpm2_qbsz > qbsize) {
	fprintf(stderr, "%s: Cannot serialized at host code\n", __func__);
	fprintf(stderr, "%s: tpm2_quote buffer size (%ld) must be >= %ld\n", __func__, qbsize, tpm2_qbsz);
	goto err2;
    }
    // fprintf(stderr, "HOST:%s: tpm2_serial=%p tpm2_qbuf=%p tpm2_qbsz=%ld LINE=%d\n", __func__, tpm2_serial, tpm2_qbuf, tpm2_qbsz, __LINE__);
    memcpy(tpm2_serial, tpm2_qbuf, tpm2_qbsz);
    // fprintf(stderr, "HOST:%s: LINE=%d\n", __func__, __LINE__);
    /* free */
    free(tpm2_qbuf);
err2:
    cbor_decref(&c_tpm2_quote);
err1:
    /* t_quote must be free ?? */
err0:
    *sz = tpm2_qbsz;
}

void
ocall_verify_tpm2_quote(uint8_t *sertpm2, int size, uint8_t *nonce, int *orc)
{
    const char	*fname = "ak_pub.pem";
    uint8_t	*s_quote = NULL;
    size_t	s_siz = 0;
    uint8_t	*s_app_hash = NULL;
    TPMS_ATTEST		tpm_atst;
    TPMT_SIGNATURE	tpm_sig;
    struct cbor_load_result	res;
    cbor_item_t		*ctpm2 = cbor_load(sertpm2, size, &res);
    struct cbor_pair	*cpair;
    int	i;
    int	rc = -1;

    VERBOSE {
	fprintf(stderr, "***************************************************\n");
	fprintf(stderr, "   TPM2 Quote is verified using %s\n", fname);
	fprintf(stderr, "       %s\n", __func__);
	fprintf(stderr, "***************************************************\n");
    }
    if (ctpm2 == NULL || cbor_typeof(ctpm2) != CBOR_TYPE_MAP) {
	fprintf(stderr, "%s: Received data is not a serialized CBOR map\n", __func__);
	goto err;
    }
    cpair = cbor_map_handle(ctpm2);
    for (i = 0; i < cbor_map_size(ctpm2); i++) {
	cbor_item_t	*key = cpair[i].key;
	char		*cp = (char*) cbor_string_handle(key);
	size_t		clen = cbor_string_length(key);

	if (!key || !cbor_isa_string(key)) continue;
	if (!strncmp(cp, "quote", clen)) {
	    /* TPM2 quote */
	    size_t		off = 0;
	    TPMS_QUOTE_INFO	*qinfo;
	    s_quote = cbor_bytestring_handle(cpair[i].value);
            s_siz   = cbor_bytestring_length(cpair[i].value);
	    Tss2_MU_TPMS_ATTEST_Unmarshal(s_quote, s_siz, &off, &tpm_atst);
	    //fprintf(stderr, "type = 0x%x (%s)\n", tpm_atst.type,
	    //		(tpm_atst.type == TPM2_ST_ATTEST_QUOTE) ?
	    //		"QUOTE" : "");
	    qinfo = &tpm_atst.attested.quote;
	    VERBOSE {
		show_tpm2quote_info("Received", qinfo);
	    }
	} else if (!strncmp(cp, "sign", clen)) {
	    /* sign */
	    uint8_t	*s_sign = cbor_bytestring_handle(cpair[i].value);
            size_t	sz = cbor_bytestring_length(cpair[i].value);
	    size_t	off = 0;
	    Tss2_MU_TPMT_SIGNATURE_Unmarshal(s_sign, sz, &off, &tpm_sig);
	} else if (!strncmp(cp, "app-hash", clen)) {
	    /* Application Hash */
	    s_app_hash = cbor_bytestring_handle(cpair[i].value);
	    if (cbor_bytestring_length(cpair[i].value) != 32) {
		fprintf(stderr, "%s: Internal error not. size(%ld)\n",
			__func__, cbor_bytestring_length(cpair[i].value));
	    }
	} 
    }
    /* TPM2 AK Signature verification */
    {
	FILE	 *fp;
	EVP_PKEY *ak_pubkey;
	if ((fp = fopen(fname, "r")) == NULL) {
	    fprintf(stderr, "Cannot find %s file.\n", fname);
	    rc = -1; goto err;
	}
	ak_pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (ak_pubkey == NULL) {
	    fprintf(stderr, "The %s file is not a PEM file.\n", fname);
	    rc = -1; goto err;
	}
	//fprintf(stderr, "%s: key type = %s\n",
	//	__func__, EVP_PKEY_get0_type_name(ak_pubkey));
	rc = verify_tpm2_quote(s_quote, s_siz, &tpm_sig, ak_pubkey);
	if (rc < 0) {
	    fprintf(stderr, "%s: Verify Failed\n", __func__);
	}
	EVP_PKEY_free(ak_pubkey);
	fclose(fp);
    }
    /* PCRs Verification */
    { /* quote.bin is a marshalled quote */
	TPMS_ATTEST	reg_atst;
	const char	*fname = "reg_quote.bin";
	FILE	 *fp;
	long	sz, rsz;
	uint8_t	*ser_qt;
	size_t	off = 0;
	int	trc;
	TPMS_QUOTE_INFO	*qinfo_peer, *qinfo_reg;
	if ((fp = fopen(fname, "r")) == NULL) {
	    fprintf(stderr, "Cannot find %s file.\n", fname);
	    rc = -1; goto err;
	}
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	ser_qt = malloc(sz);
	rsz = fread(ser_qt, 1, sz, fp);
	fclose(fp);
	if (rsz != sz) {
	    fprintf(stderr, "Cannot read the entire data of %s file.\n", fname);
	    rc = -1; goto err;
	}
	/**/
	TPM2_CALL(err, trc,
		  Tss2_MU_TPMS_ATTEST_Unmarshal(ser_qt, (size_t)sz,
						&off, &reg_atst));
	if (reg_atst.type != TPM2_ST_ATTEST_QUOTE) {
	    fprintf(stderr, "%s: The %s file is not a TPM2 quote\n", __func__, fname);
	    goto err;
	}
	qinfo_reg = &reg_atst.attested.quote;
	qinfo_peer = &tpm_atst.attested.quote;
	VERBOSE {
	    show_tpm2quote_info("Registered", qinfo_reg);
	}
	if (comp_pcr_selection(&qinfo_reg->pcrSelect,
			       &qinfo_peer->pcrSelect) != 0) {
	    fprintf(stderr, "%s: PCRregs are not identical\n", __func__);
	    goto err;
	}
    }
    /* verifying TPM2 data */
    VERBOSE {
	dump("@@@@@@@ nonce: ", nonce, 32);
	dump("@@@@@@@ TPM2 Data: ", tpm_atst.extraData.buffer, 32);
    }
    rc = 0;
err:
    *orc = rc;
}
