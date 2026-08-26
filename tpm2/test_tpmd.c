#include <cbor.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <openssl/evp.h>

#include "libsock.h"
#include "libquote.h"
#include "libmeasurement.h"
#include "tpmdaemon.h"
#include <getopt.h>

int	dflag = 0;
int	vflag = 0;

static void
usage(const char *cmd)
{
    fprintf(stderr, "%s: <path> [-d]\n", cmd);
    exit(-1);
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

static void
set_nonce(uint8_t *nonce)
{
    int	i;
    for (i = 0; i < 32; i++) {
	nonce[i] = i;
    }
}

void
show_attest(uint8_t *pkt, size_t pksz)
{
    struct cbor_load_result	res;
    cbor_item_t		*cpkt = cbor_load(pkt, pksz, &res);
    struct cbor_pair	*cpair;
    uint8_t		*nonce = NULL;
    uint8_t		*s_quote = NULL;
    size_t		s_sz = 0;
    int	i;

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
	    nonce = cbor_bytestring_handle(cpair[i].value);
	} else if (!strncmp(cp, "tpm2_quote", clen)) {
	    s_quote = cbor_bytestring_handle(cpair[i].value);
            s_sz   = cbor_bytestring_length(cpair[i].value);
	    printf("s_quote = %p, s_siz = %ld\n", s_quote, s_sz);
	}
    }
    /* s_quote is a CBOR map: [quote, sign, app-hash] */
    {
	size_t		off = 0;
	uint8_t		*tpm_quote = NULL;
	size_t		tpm_sz = 0;
	TPMS_ATTEST	tpm_atst;
	TPMS_QUOTE_INFO	*qinfo;
	TPMT_SIGNATURE	tpm_sign;
	uint8_t		*sign = NULL;
	size_t		sign_sz = 0;
	uint8_t		*apphash = NULL;
	cbor_item_t	*item;

	item = cbor_load(s_quote, s_sz, &res);
	if (cbor_typeof(item) != CBOR_TYPE_MAP) {
	    fprintf(stderr, "%s: Received tpm2_quot is not a CBOR map\n", __func__);
	}
	cpair = cbor_map_handle(item);
	for (i = 0; i < cbor_map_size(item); i++) {
	    cbor_item_t	*key = cpair[i].key;
	    char	*cp = (char*) cbor_string_handle(key);
	    size_t	clen = cbor_string_length(key);
	    if (!key || !cbor_isa_string(key)) continue;
	    if (!strncmp(cp, "quote", clen)) {
		tpm_quote = cbor_bytestring_handle(cpair[i].value);
		tpm_sz   = cbor_bytestring_length(cpair[i].value);
	    } else if (!strncmp(cp, "sign", clen)) {
		sign = cbor_bytestring_handle(cpair[i].value);
		sign_sz = cbor_bytestring_length(cpair[i].value);
	    } else if (!strncmp(cp, "app-hash", clen)) {
		apphash = cbor_bytestring_handle(cpair[i].value);
	    }
	}
	Tss2_MU_TPMS_ATTEST_Unmarshal(tpm_quote, tpm_sz, &off, &tpm_atst);
	qinfo = &tpm_atst.attested.quote;
	show_tpm2quote_info("Received", qinfo);
	dump("app-hash: ", apphash, 32);
	/* sign */
	off = 0;
	Tss2_MU_TPMT_SIGNATURE_Unmarshal(sign, sign_sz, &off, &tpm_sign);
	printf("sign alg:  ");
	if (tpm_sign.sigAlg == TPM2_ALG_SHA256) {
	    printf("TPM2_ALG_SHA256\n");
	} else {
	    printf("0x%x\n", tpm_sign.sigAlg);
	}
    }
    dump("nonce: ", nonce, 32);
err:
}

int
main(int argc, char **argv)
{
    int	rc = -1;
    char	*path;
    uint8_t	buf[1024];

    if (argc < 2) usage(argv[0]);
    path = strdup(argv[1]);
    while ((rc = getopt(argc, argv, "d")) != -1) {
	switch (rc) {
	case 'd':
	    dflag = 1; break;
	}
    }
    {
	int	con;
	con = sock_connect(path);
	if (con < 0) goto err;
	/* hello packet */
	{
	    struct tpmd_packet	pkt;
	    pkt.cmd = TPMD_REQ_HELLO;
	    pkt.len = 0;
	    printf("sending request hello\n");
	    rc = sock_send(con, &pkt, sizeof(pkt));
	    if (rc < 0) {
		printf("ERRRR\n");
	    }
	}
	/* request attest packet */
	{
	    struct tpmd_packet	head;
	    uint8_t	nonce[32];
	    uint8_t	packet[sizeof(head)+32];
	    set_nonce(nonce);
	    head.cmd = TPMD_REQ_ATTEST; head.len = 32;
	    memcpy(packet, &head, sizeof(head));
	    memcpy(&packet[sizeof(head)], nonce, 32);
	    printf("sending request attest packet-len=%ld data-len=%d\n",
		   sizeof(packet),
		   ((struct tpmd_packet*)packet)->len);
	    rc = sock_send(con, packet, sizeof(packet));
	    if (rc < 0) {
		printf("ERRRR\n");
	    }
	}
	/* receive attest packet */
	{
	    struct tpmd_packet	head;
	    rc = sock_recv(con, &head, sizeof(head));
	    if (rc < 0) printf("ERRRR\n");
	    printf("head.cmd=0x%x head.len=%d\n", head.cmd, head.len);
	    rc = sock_recv(con, buf, head.len);
	    if (rc < 0) printf("ERRRR\n");
	    show_attest(buf, head.len);
	}
	{
	    char	buf[128];
	    char	*cp;
	    printf("> ");
	    cp = fgets(buf, 128, stdin);
	    assert(cp == buf);
	}
    }
    rc = 0;
err:
    free(path);
    return rc;
}
