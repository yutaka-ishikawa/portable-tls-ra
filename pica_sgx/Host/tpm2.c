#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* for network */
#include <sys/socket.h>
//#include <sys/un.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
/**/
#include "host.h"
#include "../../tpm2/libsock.h"
#include "../../tpm2/tpmdaemon.h"

extern int vflag;
#define VERBOSE	if(vflag)

#include <sgx_urts.h>
#include <sgx_uae_service.h>	/* sgx_target_info_t might be defined */
#include "Enclave_u.h"

void
ocall_pica_measure(uint8_t *nonce, uint8_t *measure, size_t msz, size_t *sz,
		   const char *dpath)
{
    int	con;
    int	rc;
    struct tpmd_packet	head;
    uint8_t	packet[sizeof(head)+1024];

    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    fprintf(stderr, "$ Talking to Atester Daemon (%ld B) (%s) \n", msz, dpath);
    fprintf(stderr, "$     %s\n", __func__);
    fprintf(stderr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    con = sock_connect(dpath);
    if (con < 0) goto err;
    /*
     * Request Attest to daemon
     */
    head.cmd = TPMD_REQ_PICA; head.len = 32;
    memcpy(packet, &head, sizeof(head));
    memcpy(&packet[sizeof(head)], nonce, 32);
    VERBOSE {
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
    return;
err:
    fprintf(stderr, "%s: ABORT !!!\n", __func__);
    abort();
}
