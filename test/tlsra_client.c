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

#include <ptlsra.h>
#include "tlsra_test.h"

unsigned char	buf[BUF_SIZE];
unsigned char	buf2[BUF_SIZE];
int	dflag = 0;
int	tflag = 0;
int	vflag = 0;
int	pflag = 0;

static int
sslwrite(SSL *ssl, unsigned char *bp, int wsiz, int cnt)
{
    int	i, rc;
    for (i = 0; i < cnt; i++) {
	VERBOSE {
	    printf("%s: sending data size(%d)\n", __func__,  wsiz);
	}
	rc = SSL_write(ssl, bp, wsiz);
	if (rc <= 0) { /* error */
	    ERR_print_errors_fp(stderr);
	    break;
	}
	VERBOSE {
	    printf("%s: sent size(%d)\n", __func__,  rc);
	}
    }

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

    while ((rc = getopt(argc, argv, "c:dD:p:t:vP")) != -1) {
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
	case 'P':
	    pflag = 1; printf("Pflag is set\n"); break;
	}
    }
    combuf_init(buf, BUF_SIZE);
    SSL_load_error_strings();
    SSL_library_init();
    TLSRA_SSLCALLP(err, ctx, SSL_CTX_new(SSLv23_client_method()));
    /*
     *  TLS RA initialization for client side
     */
    rc = TLSRA_client_init(ctx, 1);
    if (rc != 1) {
	printf("TLSRA_client_init fails!!!!!!\n!");
	exit(-1);
    }

    /*
     * Now SSL is created from SSL_CTX.
     */
    TLSRA_SSLCALLP(err, ssl, SSL_new(ctx));

    printf("ip=0x%x port=%d\n", ip, port);
    sock = sock_connect(ip, port);
    if (sock < 0) {
	fprintf(stderr, "???? \n");
	return -1;
    }

    TLSRA_SSLCALL(err, rc, SSL_set_fd(ssl, sock));

    TLSRA_SSLCALL(err, rc, SSL_connect(ssl));
    printf("Conntect to %s\n", ipaddr(ip));

    if (pflag) {
	char	*cp, bb[128];
	printf("Pause Hit Return: "); fflush(stdout);
	cp = fgets(bb, 10, stdin);
	rc = *cp; /* for supressing warning purpose */
    }
    /* showing nonces of both client and server */
    TLSRA_show_nonce(ssl);

    /* main */
    
    switch (tflag) {
    case 0:
	printf("SSL TEST\n");
	sslwrite(ssl, buf, size, count); break;
	break;
    case 1:
	printf("TCP TEST\n");
	tcpwrite(sock, buf, size, count); break;
    }
    //myssl_inspect(ssl);
    //myssl_test_encdec(ssl);

    /* finalizing */
    myssl_shutdown(ctx, ssl);
    SYS_CALL0(ext2, rc, "close", close(sock));
ext2:
    return 0;
err:
    printf("ERROR\n");
    ERR_print_errors_fp(stderr);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    goto err;
}
