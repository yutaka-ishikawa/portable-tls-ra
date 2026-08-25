#include "libsock.h"

int
sock_listen(const char *path)
{
    struct sockaddr_un sock_addr;
    int	sock;

    if (strlen(path) > sizeof(sock_addr.sun_path)) {
	fprintf(stderr, "%s: The length of path must be no longer than 108 byte\n",
		__func__);
	return -1;
    }
    if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0 ) {
	perror("socket");
	return -1;
    }
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sun_family = AF_UNIX;
    memcpy(sock_addr.sun_path, path, sizeof(sock_addr.sun_path));
    if (bind(sock, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
	perror("bind");
	return -1;
    }
    if (chmod(path, 0777) < 0) {
	perror("chmod");
	return -1;
    }
    if (listen(sock, 10) < 0) {
	perror("listen");
	exit(-1);
    }
    return sock;
}

int
sock_connect(const char *path)
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

#ifdef LIBSOCK_TEST
int
main(int argc, char **argv)
{
    int	sock, pid;
    int	rc = -1;
    char	buf[100];
    if (argc != 3) {
	fprintf(stderr, "%s c|s <path>\n", argv[0]);
	exit(-1);
    }
    memset(buf, 0, sizeof(buf));
    if (!strcmp(argv[1], "c")) {
	char	*bp;
	/* client */
	sock = sock_connect(argv[2]);
	printf("> ");
	bp = fgets(buf, 100, stdin);
	sock_send(sock, bp, 100);
    } else {
	int	con;
	/* server */
	sock = sock_listen(argv[2]);
	if ((con = accept(sock, NULL, NULL)) < 0) {
	    perror("accept");
	    goto err;
	}
	pid = sock_client_pid(con);
	printf("Waiting for Connection ...\n");
	printf("Client PID: %d\n", pid);
	printf("Waiting for data araival from this PID ...\n");
	sock_recv(con, buf, 100);
	printf("received data: \"%s\"", buf);
	unlink(argv[2]);
    }
    rc = 0;
err:
    return rc;
}
#endif
