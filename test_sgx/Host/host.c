#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* for network */
#include <sys/socket.h>
//#include <sys/un.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
/**/

#include <sgx_urts.h>
#include <sgx_uae_service.h>	/* sgx_target_info_t might be defined */

#include <sgx_ql_quote.h>          // DCAP: QE target info / quote APIs
#include <sgx_dcap_quoteverify.h>  // (任意) 検証APIを使うなら

#include <sgx_dcap_ql_wrapper.h>   // added YI

#include "Enclave_u.h"

#define ENCLAVE_FILE "./enclave.signed.so"

#define LIBCALL(label, val, lib, fmt, ...)	\
do {				\
    val = lib;			\
    if (val != 0) {		\
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	goto label;		\
    }				\
} while(0)

void ocall_close(int fd, int *ret)
{
    *ret = close(fd);
}

void ocall_read(int fd, char *buf, size_t len, size_t *blen)
{
    int	rc;
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
    printf("%s: host side is called: env(%s) result = %p\n", __func__, env, result);
    printf("cp = %p\n", cp);
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
    *olen = fread(buf, len, 1, fp);
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
ocall_sock_serveropen(uint32_t ip, uint16_t port, int *rc)
{
    struct sockaddr_in	saddr_in;
    int	sock;

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
main(int argc, char** argv)
{
    int		*argpos;
    char	*bp;
    int		blen;
    sgx_status_t	ret;
    const char* enclave_path = ENCLAVE_FILE;

    sgx_enclave_id_t eid = 0;
    sgx_status_t st = SGX_SUCCESS;
    sgx_status_t est = SGX_SUCCESS;
    sgx_launch_token_t tok = {0};
    int updated = 0;

    // 1) Load enclave
    st = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &tok, &updated, &eid, NULL);
    if (st != SGX_SUCCESS) {
        printf("sgx_create_enclave failed: 0x%x\n", st);
        return 1;
    }
    printf("Step %d enclave_path=%s\n", __LINE__, enclave_path);

    for(int i = 0; i < argc; i++) {
	printf("argv[%d] = %s\n", i, argv[i]);
    }

    makeargs(argc, argv, &argpos, &bp, &blen);
    st = e_main(eid, &ret, argc, argpos, blen, bp);

    if (st != SGX_SUCCESS) {
        printf("e_main failed: 0x%x\n", st);
        goto out;
    }
out:
    sgx_destroy_enclave(eid);
    return 0;
}
