#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE	1024
char	buf[BUF_SIZE];

int
main(int argc, char **argv)
{
    int		sock;
    struct addrinfo hints, *inf;
    SSL		*ssl;
    SSL_CTX	*ctx;
    char	*host;
    char	*path = "/";
    char	*service = "https";
    int		rc;
    int		sz;

    if (argc != 2) {
	fprintf(stderr, "Needs host name\n");
	return -1;
    }
    host = argv[1];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rc = getaddrinfo(host, service, &hints, &inf)) != 0) {
        fprintf(stderr, "Fail to resolve ip address - %d\n", rc);
        return -1;
    }

    if ((sock = socket(inf->ai_family, inf->ai_socktype, inf->ai_protocol)) < 0) {
        perror("Fail to create a socket");
        return -1;
    }

    if (connect(sock, inf->ai_addr, inf->ai_addrlen) != 0) {
        perror("Connection error");
        return -1;
    }

    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method());
    ssl = SSL_new(ctx);
    rc = SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    printf("Conntect to %s\n", host);
    snprintf(buf, BUF_SIZE, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host);

    SSL_write(ssl, buf, strlen(buf));
    do {
        sz = SSL_read(ssl, buf, BUF_SIZE);
        rc = write(1, buf, sz);
	if (sz != rc) {
	    fprintf(stderr, "SSL_write returns %d, but expected %d\n", sz, rc);
	}
    } while(sz > 0);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();

    close(sock);

    return 0;
}
