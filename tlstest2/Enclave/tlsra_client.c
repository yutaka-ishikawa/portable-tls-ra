/*
 * Testing TLS-RA
 *	2025/10/5
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sgxenv.h>
#include <ptlsra.h>
#include "tlsra_test.h"

unsigned char	buf[BUF_SIZE];
unsigned char	buf2[BUF_SIZE];
int	dflag = 0;
int	tflag = 0;
int	vflag = 0;

union unip {
    uint8_t	addr[4];
    uint32_t	ip;
};

char *
ipaddr(uint32_t ip)
{
    static char buf[32];
    union unip	un;
    un.ip = ip;
    snprintf(buf, 32,
	     "%03d.%03d.%03d.%03d", un.addr[0], un.addr[1], un.addr[2], un.addr[3]);
    return buf;
}


static int
sslwrite(SSL *ssl, unsigned char *bp, int wsiz, int cnt)
{
    int	i, rc;
    for (i = 0; i < cnt; i++) {
	VERBOSE {
	    printf("%s: sending data size(%d)\n", __func__,  wsiz);
	}
	TLSRA_CALLN(err, rc, SSL_write(ssl, bp, wsiz));
	VERBOSE {
	    printf("%s: sent size(%d)\n", __func__,  rc);
	}
    }
err:
    return rc;
}


static int
tcpwrite(int sock, unsigned char *bp, int rsz, int cnt)
{
    ssize_t	sz;
    int	i;
    for (i = 0; i < cnt; i++) {
	VERBOSE {
	    printf("%s: sending data size(%ld)\n", __func__,  sz);
	}
	sz = write(sock, bp, rsz);
	if (sz != rsz) {
	    perror("write");
	    break;
	}
	VERBOSE {
	    printf("%s: sent size(%ld)\n", __func__,  sz);
	}
    }
    return (int)sz;
}


int
main(int argc, char **argv)
{
    int		sock;
    SSL		*ssl = NULL;
    SSL_CTX	*ctx = NULL;
    uint32_t	ip = 0x100007f;	/* localhost */
    uint16_t	port = DEFAULT_TCP_PORT;
    int		count = DEFAULT_COUNT;
    int		size = DEFAULT_SIZE;
    int		rc;

#if 0
    while ((rc = getopt(argc, argv, "c:dD:p:t:v")) != -1) {
	switch (rc) {
	case 'c':
	    count = atol(optarg); break;
	case 'd':
	    dflag = 1; break;
	case 'D':
	    ip = str2ip(optarg); break;
	case 'p':
	    port = atol(optarg); break;
	case 't':
	    tflag = atol(optarg); printf("tflag is set\n"); break;
	case 'v':
	    vflag = 1; printf("vflag is set\n"); break;
	}
    }
#endif
    combuf_init(buf, BUF_SIZE);
    SSL_load_error_strings();
    SSL_library_init();
    TLSRA_CALL0(err, ctx, SSL_CTX_new(SSLv23_client_method()));
    /*
     * Handling Handshake during client hello message
     */
    TLSRA_client_init(ctx, 1);

    /*
     * Now SSL is now created from SSL_CTX.
     */
    TLSRA_CALL0(err, ssl, SSL_new(ctx));

    printf("ip=0x%x port=%d\n", ip, port);
    sock = sock_connect(ip, port);
    if (sock < 0) {
	fprintf(stderr, "???? \n");
	return -1;
    }

    TLSRA_CALL0(err, rc, SSL_set_fd(ssl, sock));

    TLSRA_CALL1(err, rc, SSL_connect(ssl));
    printf("Conntect to %s\n", ipaddr(ip));

    /* showing nonces of both client and server */
    TLSRA_show_nonce(ssl);

    /* main */
    
    switch (tflag) {
    case 0:
	printf("SSL TEST\n");
	sslwrite(ssl, buf, size, count); break;
    case 1:
	printf("TCP TEST\n");
	tcpwrite(sock, buf, size, count); break;
    }

    //myssl_test_encdec(ssl);

    /* finalizing */
    myssl_shutdown(ctx, ssl);
    SYS_CALL0(ext2, rc, "close", close(sock));
ext2:
    return 0;
err:
    fprintf(stderr, "ERROR\n");
    ERR_print_errors_cb(myssl_printerr, NULL);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    goto err;
}
