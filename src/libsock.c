/*
 *
 */

#ifdef SGXENV
/*
 * Enclave side:
 */
#include <unistd.h>
#include <stdint.h>
#include "libsock.h"

struct timespec;
#include "pica_t.h"
int
sock_connect_daemon(const char *path)
{
    int	sock;
    ocall_sock_connect_daemon(path, &sock);
    return sock;
}

int
sock_connect(uint32_t ip, uint16_t port)
{
    int	sock;
    ocall_sock_connect(ip, port, &sock);
    return sock;
}

int
sock_serveropen(uint32_t ip, uint16_t port)
{
    int	rc;
    ocall_sock_serveropen(ip, port, &rc);
    return rc;
}

int
sock_accept(int sock)
{
    int	rc;
    ocall_sock_accept(sock, &rc);
    return rc;
}
#else
/*
 * Host-side implementation for SGX Enclave.
 * In non-SGX-Enclave environments, use pica_request_measure().
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdint.h>
#include "libsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

void
ocall_sock_connect_daemon(const char *path, int *psock)
{
    *psock = sock_connect_daemon(path);
}

void
ocall_sock_connect(uint32_t ip, uint16_t port, int *psock)
{
    *psock = sock_connect(ip, port);
}

void
ocall_sock_serveropen(uint32_t ip, uint16_t port, int *rc)
{
    *rc = sock_serveropen(ip, port);
}

void
ocall_sock_accept(int sock, int *rc)
{
    *rc = sock_accept(sock);
}

int
sock_connect_daemon(const char *path)
{
    struct sockaddr_un sock_addr;
    int	sock;

    if (strlen(path) > sizeof(sock_addr.sun_path)) {
	fprintf(stderr, "%s: The length of path must be no longer than 108 byte\n",
		__func__);
	return -1;
    }
    if((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
	perror("socket");
	return -1;
    }
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;
    memcpy(sock_addr.sun_path, path, sizeof(sock_addr.sun_path));
    if(connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
	perror("connect");
	return -1;
    }
    return sock;
}

int
sock_connect(uint32_t ip, uint16_t port)
{
    struct sockaddr_in sock_addr;
    int	on = 1;
    int	sock = -1;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket"); goto err;
    }
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(port);
    bcopy(&ip, &sock_addr.sin_addr, sizeof(ip));
    if(connect(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
	perror("connect"); goto err;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int)) < 0) {
	perror("setsockopt");
    }
err:
    return sock;
}

int
sock_serveropen(uint32_t ip, uint16_t port)
{
    struct sockaddr_in	saddr_in;
    int	sock = -1;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0 ) {
	perror("socket");
	goto err;
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
	goto err;
    }
    if (listen(sock, 10) < 0) {
	fprintf(stderr, "Listen error\n");
	goto err;
    }
err:
    return sock;
}

int
sock_accept(int sock)
{
    struct sockaddr	saddr;
    socklen_t	addrlen;
    int	on = 1;
    int	fd = -1;

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
sock_client_pid(int sock)
{
    struct ucred	cred;
    socklen_t		len = sizeof(cred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        perror("getsockopt(SO_PEERCRED)");
        return -1;
    }
    return cred.pid;
}

int
sock_send(int sock, void *buf, size_t size)
{
    size_t	totsz = 0;

    do {
	size_t	sz = write(sock, buf + totsz, size - totsz);
	if (sz <= 0) goto err;
	totsz += sz;
    } while (totsz < size);
    return 0;
err:
    perror("sock_send");
    return -1;
}

int
sock_recv(int sock, void *buf, size_t size)
{
    size_t	totsz = 0;
    int	rc = -2;

    do {
	size_t	sz = recv(sock, buf + totsz, size - totsz, 0);
	if (sz < 0) goto err;
	if (sz == 0 && totsz == 0) {
	    /* disconnected */
	    rc = -1;
	    goto eos;
	}
	totsz += sz;
    } while (totsz < size);
    return 0;
err:
    perror("sock_recv");
eos:
    return rc;
}

#endif
