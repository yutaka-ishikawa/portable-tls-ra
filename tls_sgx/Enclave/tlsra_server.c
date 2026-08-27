/*
 * Testing Portable TLS-RA
 *	2026/Jan/3
 *
 *	-d debug
 *	-v verbose
 *	-V verify Client certificate
 *	-C require Client certificate for CA/my_ca.crt
 *		   This is a normal action using CA cert file
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
//#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <sgxenv.h>
#include <ptlsra.h>
#include "tlsra_test.h"

unsigned char	buf[BUF_SIZE];
unsigned char	buf2[BUF_SIZE];
int	dflag = 0;	/* debug */
int	rflag = 0;	/* remote attestation */
int	tflag = 0;
int	vflag = 0;	/* verbose */
int	Vflag = 0;	/* verify */
int	Cflag = 0;	/* require Client Certificate */
int	atflag = 0;	/* using Attester Daemon */
char	*dpath;
int	count = DEFAULT_COUNT;
uint16_t port = DEFAULT_TCP_PORT;

static int
getoption(int argc, char **argv)
{
    int	i;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    switch (argv[i][1]) {
	    case 'C': Cflag = 1; break;
	    case 'c': if (i > argc) goto err;
		count = atol(argv[i+1]); i++; break;
	    case 'd':
		dflag = 1; break;
	    case 'D': /* using Attester Daemon */
		atflag = 1; 
		dpath = strndup(argv[i+1], 108); i++;
		break;
	    case 'p': if (i > argc) goto err;
		port = atol(argv[i+1]); i++; break;
	    case 'r': /* remote attestation */
		rflag = atol(argv[i+1]); i++; break;
	    case 't': if (i > argc) goto err;
		tflag = atol(argv[i+1]); i++; break;
	    case 'v':
		vflag = 1; break;
	    case 'V': /* verify */
		Vflag = 1; break;
	    }
	} else {
	    break;
	}
    }
    return i;
err:
    printf("A few arguments\n");
    return -1;
}

/*
 * Client certificate verification
 */
static int
verify(int ok, X509_STORE_CTX *ctx)
{
    X509	*x509 = X509_STORE_CTX_get_current_cert(ctx);

    fprintf(stderr, "%s: verify X509\n", __func__);
    if (x509 == NULL) {
	fprintf(stderr, "%s: Client Cert verificaion fails.\n", __func__);
	return ok;
    }
    printf("Subject:\n"); TLSRA_show_subject_name(x509);
    printf("Issuer:\n"); TLSRA_show_issuer_name(x509);
    fprintf(stderr, "%s: Client Cert verificaion ok = %d\n", __func__, ok);
    return ok;
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
	    ERR_print_errors_cb(myssl_printerr, NULL);
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


int
main(int argc, char **argv)
{
    int		sock, csock;
    SSL_CTX	*ctx;
    SSL		*ssl;
    int		size = DEFAULT_SIZE;
    int		rc;
    int		error = 0;
    char	*env = getenv("SSL_PROVIDER");

    DEBUG {
	printf("argc = %d\n", argc);
    }
    getoption(argc, argv);
    memset(buf, 0, BUF_SIZE);
    /* SSL initialization */
    if (env && *env != 0) {
	OSSL_PROVIDER	*prov = OSSL_PROVIDER_load(NULL, env);
	printf((prov == NULL ? "Cannot load %s\n" : "Loaded %s\n"), env);
    }
#if !(SGX_ENCLAVE || SGX_ENCLAVE_WITH_TPM2)
    printf("default-cipher-list: %s\n", OSSL_default_cipher_list());
    printf("default-ciphersuites: %s\n", OSSL_default_ciphersuites());
    SSL_load_error_strings();
    SSL_library_init();
#else
    printf("%s: Skipping SSL library init in SGX\n", __func__);
#endif
    TLSRA_SSLCALLP(err3, ctx, SSL_CTX_new(SSLv23_server_method()));

    /*
     * Remote-Attestion TLS RA initialization
     *		- Requiring Client cert
     *		- callback function, clent_hello_cb is set (on_client_hello)
     */
    TLSRA_server_init(ctx, rflag);

    /*
     * This is for normal TLS action:
     *     Client Certificate
     *		Client CA file:
     *		  $ cat caA.pem caB.pem caC.pem > truststore.pem
     *		  calist = SSL_load_client_CA_file("truststore.pem");
     */
    if (Cflag) {
	/* require client certificate for CA/my_ca.crt */
	STACK_OF(X509_NAME) *calist;
	printf("Request Client Certificate for CA/my_c.crt !!!\n");
	TLSRA_SSLCALLP(err4, calist, SSL_load_client_CA_file("CA/my_ca.crt"));
	SSL_CTX_set_client_CA_list(ctx, calist);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify);
	SSL_CTX_set_verify_depth(ctx, 10);

    }
    /*
     * SSL is now created from SSL_CTX.
     */
    TLSRA_SSLCALLP(err3, ssl, SSL_new(ctx));
    {
	int priority = 0;
	const char *lst = SSL_get_cipher_list(ssl, priority);
	const char *ver = SSL_get_version(ssl);
	VERBOSE {
	    printf("cipher_list: %s\n", lst == NULL ? "No cipers" : lst);
	    printf("Server Version: %s\n", ver);
	}
    }

    /* socket listen */
    printf("*********************************************\n");
    printf("****** NOW Listning requests at port = %d\n", port);
    printf("*********************************************\n");
    sock = sock_serveropen(INADDR_ANY, port);
    if (sock < 0) {
	fprintf(stderr, "???? \n");
	return -1;
    }
    VERBOSE {
	printf("sock %d\n", sock);
    }

    /* socket accept */
    csock = sock_accept(sock);
    VERBOSE {
	printf("accepted %d\n", csock);
    }
    TLSRA_SSLCALL(err, rc, SSL_set_fd(ssl, csock));
    VERBOSE {
	printf("Going to accept\n");
    }
    TLSRA_SSLCALL(err, rc, SSL_accept(ssl));

    VERBOSE {
	printf("Conntected\n");
	printf("Server Version: %s\n", SSL_get_version(ssl));
	/* showing nonces of both client and server */
	TLSRA_show_nonce(ssl);
	{
	    X509	*cert = SSL_get_peer_certificate(ssl);
	    printf("cert = %p\n", cert);
	}
    }
    /*
     *
     */
    printf("***** SSL TEST *****\n");
    error = sslread(ssl, buf, size, count);
    if (error == 0) {
	printf("Success:\n");
    }
    goto skip;
    /* finalizing */
err:
    printf("ERROR!!\n");
skip:
    myssl_shutdown(ctx, ssl);
    /* closing comm socket */
    TLSRA_SYSCALL(err2, rc, close(csock), "close");
err2:
    /* closing socket */
    TLSRA_SYSCALL(err3, rc, close(sock), "close");
    return 0;
err3:
    printf("SSL_CTX_new() fails\n");
    return -1;
err4:
    printf("Cannot load client CA\n");
}
