/*
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
//#include <sys/un.h>
#include <linux/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libsock.h"

union unip {
    uint8_t	addr[4];
    uint32_t	ip;
};

uint32_t
str2ip(char *str)
{
#ifdef SGX_ENCLAVE
    printf("%s: NEEDS TO IMPLEMENT this function\n", __func__);
    abort();
    return 0;
#else
    union unip	un;
    int		ad[4], i;
    sscanf(str, "%d.%d.%d.%d", &ad[0], &ad[1], &ad[2], &ad[3]);
    for (i = 0; i < 4; i++) {
	un.addr[i] = ad[i];
    }
    return un.ip;
#endif
}

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

int
sock_serveropen(uint32_t ip, uint16_t port)
{
    struct sockaddr_in	saddr_in;
    int	sock;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
	perror("socket");
	return -1;
    }
    { /* set REUSEADDR */
	int	one = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    memset((char*)&saddr_in, 0, sizeof(saddr_in));
    saddr_in.sin_addr.s_addr = htonl(ip);
    saddr_in.sin_family = AF_INET;
    saddr_in.sin_port = htons(port);
    if (bind(sock, (struct sockaddr*)&saddr_in, sizeof(saddr_in)) < 0) {
	perror("bind");
	return -1;
    }
    if (listen(sock, 10) < 0) {
	fprintf(stderr, "Listen error\n");
	exit(-1);
    }
    return sock;
}

int
sock_accept(int sock)
{
    struct sockaddr	saddr;
    socklen_t	addrlen;
    int	on = 1;
    int	fd;

    addrlen = sizeof(saddr);
    if ((fd = accept(sock, (struct sockaddr*) &saddr, &addrlen)) < 0) {
	fprintf(stderr, "Error\n");
	exit(-1);
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int)) < 0) {
	perror("setsockopt");
    }
    return fd;
}

int
sock_connect(uint32_t ip, uint16_t port)
{
    struct sockaddr_in sock_addr;
    int on = 1;
    int	sock;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket");
	return -1;
    }
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    bcopy(&ip, &sock_addr.sin_addr, sizeof(ip));
    if(connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
	perror("connect");
	return -1;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int)) < 0) {
	perror("setsockopt");
    }
    return sock;
}

void
combuf_init(unsigned char *bp, int sz)
{
    int		i;
    for (i = 0; i < sz; i++) {
	bp[i] = '0' + i%10;
    }
}

void
combuf_vryfy(unsigned char *bp, int sz)
{
    int		err = 0;
    int		i;
    for (i = 0; i < sz; i++) {
	if (bp[i] != '0' + i%10) {
	    printf("%s: expect(%x) data(%x) in %d\n", __func__, '0'+ i%10, bp[i], i);
	    err++;
	}
    }
    if (!err) printf("%s: Correct message is received (%d)\n", __func__, sz);
}

void
dump(const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(stderr, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(stderr, "%02x:", bf[i]);
    }
    fprintf(stderr, "\n");
}

void
myssl_shutdown(SSL_CTX *ctx, SSL *ssl) {
    int	rc, count = 0;
    do {
	rc = SSL_shutdown(ssl);
	count++;
    } while (rc == 0);
    if (count > 1) {
	printf("SSL_shutdown has been issued %d times\n", count);
    }
    if (rc < 0) {
	ERR_print_errors_fp(stderr);
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();
}
