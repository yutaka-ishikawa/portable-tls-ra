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

#include "libsock.h"
#include "libmyssl.h"
#include "mytest.h"

unsigned char	buf[BUF_SIZE];
unsigned char	buf2[BUF_SIZE];
int	dflag = 0;
int	tflag = 0;
int	vflag = 0;
int	pflag = 0;

static int
on_client_cert(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
#define O_SIZE	1024
    unsigned char	report[512];
    size_t	sz;
    unsigned char	nonce[O_SIZE];

    DEBUG {
	fprintf(stderr, "%s: is called !!!!!!!!!!!!!!!\n", __func__);
    }
    fprintf(stderr, "TLS-RA mode\n");
    /* nonce from client */
    sz = SSL_get_server_random(ssl, nonce, O_SIZE);
    if (sz > 0) {
	dump("\tnonce = ", nonce, sz);
    } else {
	printf("\tNo nonce has been received\n");
    }
    memset(report, 0, sizeof(report));
    memcpy(report, nonce, sz > 512 ? 512 : sz);
    if (mysslra_x509(x509, pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
		     report, sz) != 1) {
	fprintf(stderr, "Cannot generate certificate\n");
	exit(-1);
    }
    fprintf(stderr, "\tSubject: "); myssl_show_subject_name(*x509);
    fprintf(stderr, "\tIssuer: "); myssl_show_issuer_name(*x509);
    return 1; /* success */
}

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

static int
mywrite(int sock, SSL *ssl, unsigned char *bp, int wsiz, int cnt)
{
    int	i, rc = 0;
    int	wsz, sz;
    cnt = 1;
    for (i = 0; i < cnt; i++) {
	VERBOSE {
	    printf("%s: sending data size(%d)\n", __func__,  wsiz);
	}
	myssl_enc(ssl, buf2, &wsz, bp, wsiz);
	printf("%s; Encrypted size = %d\n", __func__, wsz);
	sz = write(sock, buf2, wsz);
	if (sz != wsz) {
	    perror("write");
	    break;
	}
	if (rc <= 0) { /* error */
	    ERR_print_errors_fp(stderr);
	    break;
	}
	VERBOSE {
	    printf("%s: sent Encrypt data size(%d)\n", __func__,  rc);
	}
    }
    return rc;
}

/*
 * Server certificate verification
 */
static int
verify(int ok, X509_STORE_CTX *ctx)
{
#define O_SIZE	1024
    X509	*x509;
    SSL		*ssl;
    size_t	sz;
    unsigned char nonce[O_SIZE];

    DEBUG {
	fprintf(stderr, "%s: Server certificate verification\n", __func__);
    }
    x509 = X509_STORE_CTX_get_current_cert(ctx);
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (x509 == NULL || ssl == NULL) {
	fprintf(stderr, "%s: Server Cert verificaion fails.\n", __func__);
	return ok;
    }
    sz = SSL_get_client_random(ssl, nonce, O_SIZE);
    DEBUG { /* debug */
	int	depth = X509_STORE_CTX_get_error_depth(ctx);
	char	subj[256];
	fprintf(stderr, "\tSubject: "); myssl_show_subject_name(x509);
	fprintf(stderr, "\tIssuer: "); myssl_show_issuer_name(x509);
	fprintf(stderr, "\nServer Nonce: size = %ld\n", sz);
	if (sz > 0) {
	    dump("\tnonce = ", nonce, sz);
	}
	X509_NAME_oneline(X509_get_subject_name(x509), subj, sizeof(subj));
	fprintf(stderr, "\tok=%d depth=%d ok=%d subject=%s\n", ok, depth, ok, subj);
	// myssl_dump_x509(x509);
    }
    ok = mysslra_verify(ok, x509, nonce);
    if (!ok) {
	int err   = X509_STORE_CTX_get_error(ctx);
	fprintf(stderr, "Server Cert verificaion fails.\n\t reason = %s\n",
		X509_verify_cert_error_string(err));
	// myssl_dump_x509(x509);
	fprintf(stderr, "But become OK\n");
	ok = 1;
    }
    fprintf(stderr, "%s: Server Cert verificaion ok = %d\n", __func__, ok);
    return ok;
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
    SSL_CALL0(err, ctx, SSL_CTX_new(SSLv23_client_method()));
    /*
     * Handling Handshake during client hello message
     */
    SSL_CTX_set_client_cert_cb(ctx, on_client_cert);

    /* Require Server certificate and verification*/
    /* CA cert (PEM) */
    //SSL_CALL0(err, rc, SSL_CTX_load_verify_locations(ctx, "./CA/my_ca.crt", NULL));
    SSL_CALL0(err, rc, SSL_CTX_load_verify_dir(ctx, "./CA"));
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify);
    SSL_CTX_set_verify_depth(ctx, 10);
    /**/

    /*
     * Now SSL is now created from SSL_CTX.
     */
    SSL_CALL0(err, ssl, SSL_new(ctx));

    printf("ip=0x%x port=%d\n", ip, port);
    sock = sock_connect(ip, port);
    if (sock < 0) {
	fprintf(stderr, "???? \n");
	return -1;
    }

    SSL_CALL0(err, rc, SSL_set_fd(ssl, sock));

    SSL_CALL1(err, rc, SSL_connect(ssl));
    printf("Conntect to %s\n", ipaddr(ip));

    if (pflag) {
	char	*cp, bb[128];
	printf("Pause Hit Return: "); fflush(stdout);
	cp = fgets(bb, 10, stdin);
	rc = *cp; /* for supressing warning purpose */
    }
    /* showing nonces of both client and server */
    myssl_show_nonce(ssl);

    /* main */
    
    switch (tflag) {
    case 0:
	printf("SSL TEST\n");
	sslwrite(ssl, buf, size, count); break;
    case 1:
	printf("TCP TEST\n");
	tcpwrite(sock, buf, size, count); break;
    case 2: /* testing encryp/decrypt */
	printf("MYENC TEST\n");
	mywrite(sock, ssl, buf, size, count); break;
    }
    myssl_inspect(ssl);

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
