#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
/* for network */
#include <sys/socket.h>
//#include <sys/un.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
/**/
#include "Enclave_u.h"
#include "host.h"

int	oflag = 0;
int	dflag = 0;
int	rflag = 0;
int	tflag = 0;
int	vflag = 0;
int	Vflag = 0;
int	Cflag = 0;
int	count = DEFAULT_COUNT;
uint16_t port = DEFAULT_TCP_PORT;
int	atflag = 0;
char	*dpath = NULL;

#define OCALL_PRINT(oflag)	if (oflag) printf("OCALL %s INVOKED\n", __func__);

void ocall_time(uint64_t *tp)
{
    time_t	tm;

    OCALL_PRINT(oflag);
    time(&tm);
    *tp = (uint64_t) tm;
}

void ocall_close(int fd, int *ret)
{
    OCALL_PRINT(oflag);
    *ret = close(fd);
}

void ocall_open(const char *path, int flags, int *ret)
{
    OCALL_PRINT(oflag);
    *ret = open(path, flags);
}

void ocall_write(int fd, const char *buf, size_t len, size_t *wlen)
{
    OCALL_PRINT(oflag);
    *wlen = write(fd, buf, len);
}

void ocall_read(int fd, char *buf, size_t len, size_t *blen)
{
    int	rc;
    OCALL_PRINT(oflag);
    rc = read(fd, buf, len);
    *blen = rc;
}

void ocall_print(const char *s)
{
    printf("%s", s);
}

void ocall_puts(const char *s) {
    puts(s);
}

void ocall_putn(const char *s, int len, size_t *wlen) {
    char	ch = '\n';
    size_t	sz;
    sz = fwrite(s, len, 1, stdout);
    fwrite(&ch, 1, 1, stdout);
    sz++;
    *wlen = sz;
}

void ocall_getenv(const char *env, char *result, int len)
{
    char	*cp = getenv(env);

    if (cp) {
	if (len < strlen(cp)) {
	    fprintf(stderr,
		    "Cannot copy due to smaller buffer size: getenv(%s)=%s\n",
		    env, cp);
	    *result = 0;
	} else {
	    strncpy(result, cp, len);
	}
    } else {
	*result = 0;
    }
}

void ocall_get_current_time(uint64_t *p_current_time)
{
    time_t rawtime;
    OCALL_PRINT(oflag);
    time (&rawtime);
    if (!p_current_time)
        return;
    *p_current_time = (uint64_t) rawtime;
}


void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/*
 *
 */
void
ocall_readfile(const char *fname, char *buf, size_t ilen, size_t *olen)
{
    FILE	*fp;
    size_t	len;
    int		rc;
    *olen = 0;
    printf("%s: current directory is %s\n", __func__, get_current_dir_name());
    printf("%s: file name = %s\n", __func__, fname);
    if ((fp = fopen(fname, "r")) == NULL) {
	fprintf(stderr, "Error: reading file %s\n", fname);
	perror("fopen");
	goto err0;
    }
    LIBCALL(err1, rc, fseek(fp, 0, SEEK_END), "fseek error");
    len = ftell(fp);
    if (len > ilen) {
	fprintf(stderr, "Error: too small buffer size for reading file: %s\n", fname);
	goto err1;
    }
    LIBCALL(err1, rc, fseek(fp, 0, SEEK_SET), "fseek error");
    *olen = fread(buf, 1, len, fp);
    if (*olen != len) {
	fprintf(stderr, "Error: Cannot read entire file: %s (%ld, %ld)\n", fname, *olen, len);
	*olen = 0;
    }
err1:
    fclose(fp);
err0:
    return;
}

void
ocall_sock_connect(uint32_t ip, uint16_t port, int *psock)
{
    struct sockaddr_in sock_addr;
    int	on = 1;
    int	sock = -1;

    OCALL_PRINT(oflag);
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
    *psock = sock;
}

void
ocall_sock_serveropen(uint32_t ip, uint16_t port, int *rc)
{
    struct sockaddr_in	saddr_in;
    int	sock;

    OCALL_PRINT(oflag);
    *rc = -1;
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
    *rc = sock;
err:
}

void
ocall_sock_accept(int sock, int *rc)
{
    struct sockaddr	saddr;
    socklen_t	addrlen;
    int	on = 1;
    int	fd;

    OCALL_PRINT(oflag);
    *rc = -1;
    addrlen = sizeof(saddr);
    if ((fd = accept(sock, (struct sockaddr*) &saddr, &addrlen)) < 0) {
	fprintf(stderr, "Error\n");
	exit(-1);
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int)) < 0) {
	perror("setsockopt");
    }
    *rc = fd;
}

int
makeargs(int argc, char **argv, int **argpos, char **buf, int *buflen)
{
    int	i, len = 0, pos = 0;
    char	*tbuf;
    int		*targpos;
    int	rc;

    for (i = 0; i < argc; i++) {
        len += strlen(argv[i]) + 1;
    }
    *buflen = len;
    *buf = tbuf = malloc(len);
    *argpos = targpos = malloc(sizeof(int)*argc);
    for (i = 0; i < argc; i++) {
	targpos[i] = pos;
	len = strlen(argv[i]);
	strcpy(&tbuf[pos], argv[i]);
	pos += len + 1;
    }
    return 0;
}

int
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
		/* No meaning in the host code */
		atflag = 1; 
		dpath = strndup(argv[i+1], 108); i++;
		break;
	    case 'p': if (i > argc) goto err;
		port = atol(argv[i+1]); i++; break;
	    case 'r': /* remote attestation */
		if (i > argc) goto err;
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

void
ocall_getclocktime(int64_t *sec, int64_t *nsec)
{
    struct timespec ts;

    fprintf(stderr, "%s: CALLED\n", __func__);
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
	perror("ocall_getclocktime");
	*sec = 0;
	*nsec = 0;
	return;
    }
    *sec  = (int64_t)ts.tv_sec;
    *nsec = (int64_t)ts.tv_nsec;
    fprintf(stderr, "%s: sec(%d) nsec(%d)\n", __func__, *sec, *nsec);
}

/*
 * The following functions are defined in the following files:
 * SampleCode/SampleAttestedTLS/sgxssl/Linux/sgx/libsgx_usgxssl/uunistd.cpp
 * Those functions are copied because of tracing which Linux functions are
 * invoked from Enclave during SSL communication.
 * 
 */
#if 0
ssize_t
u_sgxssl_write(int fd, const void* buf, size_t n)
{
    ssize_t ret;
    OCALL_PRINT(oflag);
    ret = write(fd, buf, n);
    return ret;
}
	
ssize_t
u_sgxssl_read(int fd, void* buf, size_t count)
{
    ssize_t ret;
    OCALL_PRINT(oflag);
    ret = read(fd, buf, count);
    return ret;
}
	
int
u_sgxssl_close(int fd)
{
    int ret;
    OCALL_PRINT(oflag);
    ret = close(fd) ;
    return ret;
}

int
u_sgxssl_open(const char *filename, int flags)
{
    OCALL_PRINT(oflag);
    if (filename == NULL) return -1;
    int ret = open(filename, flags);
    return ret;
}

#include <sys/timeb.h>
void
u_sgxssl_ftime(void * timeptr, uint32_t timeb_len)
{
    //SGX_ASSERT_STRUCT_SIZE(struct timeb, timeb_len);
    OCALL_PRINT(oflag);
    ftime((struct timeb *) timeptr);
}

void u_sgxssl_usleep(int micro_seconds)
{
    OCALL_PRINT(oflag);
    usleep(micro_seconds);
}
#endif
