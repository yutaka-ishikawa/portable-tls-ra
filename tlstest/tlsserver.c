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
#include <openssl/provider.h>

#include "libsock.h"
#include "libmyssl.h"
#include "mytest.h"

unsigned char	buf[BUF_SIZE];
unsigned char	buf2[BUF_SIZE];
int	dflag = 0;
int	rflag = 0;	/* remote attestation */
int	tflag = 0;
int	vflag = 0;
int	Vflag = 0;	/* verify */
int	Cflag = 0;	/* require Client Certificate */

/*
 * Client certificate verification
 */
static int
verify(int ok, X509_STORE_CTX *ctx)
{
    X509	*x509 = X509_STORE_CTX_get_current_cert(ctx);

    if (x509 == NULL) {
	fprintf(stderr, "%s: Client Cert verificaion fails.\n", __func__);
	return ok;
    }
    printf("Subject: "); myssl_show_subject_name(x509);
    printf("Issuer: "); myssl_show_issuer_name(x509);
    fprintf(stderr, "%s: Client Cert verificaion ok = %d\n", __func__, ok);
    return ok;
}

/*
 * On the clientHello message, the server certificate is dynamically created.
 */
static int
on_client_hello(SSL *ssl, int *al, void *arg)
{
    unsigned char	report[512];
    int	len;
    int	rc;
    // SSL_set_msg_callback(con, msg_callback);
    printf("Certificate initializaion\n");
    {
	const unsigned char *nonce = NULL;
	/* nonce from client */
	len = SSL_client_hello_get0_random(ssl, &nonce);
	if (len > 0) {
	    dump("\tnonce = ", nonce, len);
	} else {
	    printf("\tNo nonce has been received\n");
	}
	memset(report, 0, sizeof(report));
	memcpy(report, nonce, len > 512 ? 512 : len);
    }
    //SSL_CALL1(err3, rc, SSL_use_certificate_file(ssl, "public.key", SSL_FILETYPE_PEM));
    //SSL_CALL1(err3, rc, SSL_use_PrivateKey_file(ssl, "private.key", SSL_FILETYPE_PEM));
    if (rflag) {
	X509		*x509;
	EVP_PKEY	*pkey;
	printf("TLS-RA mode\n");
	if (mysslra_x509(&x509, &pkey, "./CA/my_ca.crt", "./CA/my_ca.key",
			 report, len) != 1) {
	    fprintf(stderr, "Cannot generate certificate\n");
	    exit(-1);
	}
	printf("Subject: "); myssl_show_subject_name(x509);
	printf("Issuer: "); myssl_show_issuer_name(x509);
	SSL_CALL1(err3, rc, SSL_use_certificate(ssl, x509));
	SSL_CALL1(err3, rc, SSL_use_PrivateKey(ssl, pkey));
    } else {
	SSL_CALL1(err3, rc, SSL_use_certificate_file(ssl, "server.crt", SSL_FILETYPE_PEM));
	SSL_CALL1(err3, rc, SSL_use_PrivateKey_file(ssl, "server.key", SSL_FILETYPE_PEM));
    }
    /* success */
    return SSL_CLIENT_HELLO_SUCCESS;
err3: /* error */
    return SSL_CLIENT_HELLO_ERROR;
}

static int
sslread(SSL *ssl, unsigned char *bp, int rsz, int count)
{
    int sz, i;
    int	err = 0;
    for (i = 0; i < count; i++) {
	VERBOSE {
	    printf("%s: calling SSL_READ (%p)\n", __func__,  bp);
	}
	sz = SSL_read(ssl, bp, rsz);
	if (sz != rsz) {
	    err++;
	    fprintf(stderr, "received size(%d) expected size(%d)\n", sz, rsz);
	    ERR_print_errors_fp(stderr);
	}
	VERYFY {
	    combuf_vryfy(bp, sz);
	}
    }
    return err;
}

static int
tcpread(int sock, unsigned char *bp, int rsz, int cnt)
{
    int sz, i;
    int	err = 0;
    for (i = 0; i < cnt; i++) {
	sz = read(sock, bp, rsz);
	if (sz != rsz) {
	    err++;
	    fprintf(stderr, "received size(%d) expected size(%d)\n", sz, rsz);
	}
	VERBOSE {
	    combuf_vryfy(bp, sz);
	}
    }
    return err;
}

static int
myread(int sock, SSL *ssl, unsigned char *bp, int rsz, int count)
{
    int sz, i;
    int	err = 0;
    count = 1;
    for (i = 0; i < count; i++) {
	VERBOSE {
	    printf("%s: calling read (%p)\n", __func__,  bp);
	}
	sz = read(sock, buf2, rsz);
	if (sz != rsz) {
	    err++;
	    fprintf(stderr, "received size(%d) expected size(%d)\n", sz, rsz);
	    continue;
	}
	{
	    int	i;
	    printf("HOHOHOHOHO\n");
	    for (i = 0; i < 100; i++) {
		printf("%c", buf2[i]);
	    }
	    printf("\n");
	}
	myssl_dec(ssl, bp, &sz, buf2, rsz);
	printf("%s; Decrypted size = %d\n", __func__, sz);
	VERYFY {
	    combuf_vryfy(bp, sz);
	}
	{
	    int	i;
	    printf("HIHIHIHIHIHIHIHI\n");
	    for (i = 0; i < 100; i++) {
		printf("%c", *(bp + i));
	    }
	    printf("\n");
	}
    }
    return err;
}


int
main(int argc, char **argv)
{
    int		sock, csock;
    SSL_CTX	*ctx;
    SSL		*ssl;
    uint16_t	port = DEFAULT_TCP_PORT;
    int		count = DEFAULT_COUNT;
    int		size = DEFAULT_SIZE;
    int		rc;
    int		error = 0;
    char	*env = getenv("SSL_PROVIDER");

    while ((rc = getopt(argc, argv, "Cc:dp:rt:vV")) != -1) {
	switch (rc) {
	case 'C': Cflag = 1; break;
	case 'c':
	    count = atol(optarg); break;
	case 'd':
	    dflag = 1; break;
	case 'p':
	    port = atol(optarg); break;
	case 'r':
	    rflag = 1; break;
	case 't':
	    tflag = atol(optarg); printf("tflag is set\n"); break;
	case 'v':
	    vflag = 1; printf("vflag is set\n"); break;
	case 'V': /* verify */
	    Vflag = 1; printf("Vflag is set\n"); break;
	}
    }
    memset(buf, 0, BUF_SIZE);
    /* SSL initialization */
    if (env) {
	OSSL_PROVIDER	*prov = OSSL_PROVIDER_load(NULL, env);
	printf((prov == NULL ? "Cannot load %s\n" : "Loaded %s\n"), env);
    }
    printf("default-cipher-list: %s\n", OSSL_default_cipher_list());
    printf("default-ciphersuites: %s\n", OSSL_default_ciphersuites());
    SSL_load_error_strings();
    SSL_library_init();
    SSL_CALL0(err3, ctx, SSL_CTX_new(SSLv23_server_method()));
    /*
     * Handling Handshake during client hello message
     */
    SSL_CTX_set_client_hello_cb(ctx, on_client_hello, NULL);
    /*
     * Client Certificate
     *		Client CA file:
     *		  $ cat caA.pem caB.pem caC.pem > truststore.pem
     *		  calist = SSL_load_client_CA_file("truststore.pem");
     */
    if (Cflag) {
	STACK_OF(X509_NAME) *calist;
	printf("Request Client Certificate !!!\n");
	SSL_CALL0(err3, calist, SSL_load_client_CA_file("CA/my_ca.crt"));
	SSL_CTX_set_client_CA_list(ctx, calist);	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify);
	SSL_CTX_set_verify_depth(ctx, 10);

    }
    /*
     * SSL is now created from SSL_CTX.
     */
    SSL_CALL0(err3, ssl, SSL_new(ctx));
    {
	int priority = 0;
	const char *lst = SSL_get_cipher_list(ssl, priority);
	const char *ver = SSL_get_version(ssl);

	printf("cipher_list: %s\n", lst == NULL ? "No cipers" : lst);
	printf("Server Version: %s\n", ver);
    }

    /* socket listen */
    printf("port = %d\n", port);
    sock = sock_serveropen(INADDR_ANY, port);
    if (sock < 0) {
	fprintf(stderr, "???? \n");
	return -1;
    }
    printf("sock %d\n", sock);

    /* socket accept */
    csock = sock_accept(sock);
    printf("accepted %d\n", csock);
    SSL_CALL1(err, rc, SSL_set_fd(ssl, csock));
    printf("Going to accept\n");
    SSL_CALL1(err, rc, SSL_accept(ssl));

    printf("Conntected\n");
    printf("Server Version: %s\n", SSL_get_version(ssl));
    /* showing nonces of both client and server */
    myssl_show_nonce(ssl);

    {
	X509	*cert = SSL_get_peer_certificate(ssl);
	printf("cert = %p\n", cert);
    }

    switch (tflag) {
    case 0:
	printf("SSL TEST\n");
	error = sslread(ssl, buf, size, count);
	break;
    case 1:
	printf("TCP TEST\n");
	error = tcpread(csock, buf, size, count);
	break;
    case 2: /* testing encryp/decrypt */
	printf("MYENC TEST\n");
	myread(csock, ssl, buf, size, count); break;
    }
    if (error == 0) {
	printf("Success:\n");
    }
    myssl_inspect(ssl);

#if 0
    /* testing encryp/decrypt */
    printf("Testing Enrypt/Decrypt\n");
    myssl_test_encdec(ssl);
#endif
    goto skip;
    /* finalizing */
err:
    printf("ERROR!!\n");
skip:
    myssl_shutdown(ctx, ssl);
    /* closing comm socket */
    SYS_CALL0(err2, rc, "close", close(csock));
err2:
    /* closing socket */
    SYS_CALL0(err3, rc, "close", close(sock));
err3:
    return 0;
}
