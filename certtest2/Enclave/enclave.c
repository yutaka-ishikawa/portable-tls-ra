#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "Enclave_t.h"
#include "sgxenv.h"

extern int main(int, char**);

static char	envbuf[1024];
FILE	*stderr;

/*
 * C library compatibility
 */
int
fprintf(FILE *fp, const char *fmt, ...)
{
    char	*bp = NULL;
    size_t	len = 0;
    va_list arg;
    /* determine required size */
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    len++;
    bp = malloc(len);
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    ocall_print(bp);
    free(bp);
}

int
printf(const char *fmt, ...)
{
    char	*bp = NULL;
    size_t	len = 0;
    va_list arg;
    /* determine required size */
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    len++;
    bp = malloc(len);
    va_start(arg, fmt);
    len = vsnprintf(bp, len, fmt, arg);
    va_end(arg);
    ocall_print(bp);
    free(bp);
}

int
fputc(int ch, FILE*)
{
    int	rc;
    rc = printf("%c", ch);
    return rc;
}

int
fputs(const char *str, FILE*)
{
    int	rc;
    rc = printf("%s\n", str);
    return rc;
}

size_t
fwrite(const void *ptr, size_t sz, size_t nm, FILE *)
{
    size_t	wlen = 0;
    ocall_putn(ptr, sz*nm, &wlen);
    return wlen;
}

char *
getenv(const char *env)
{
    int	len = 1024;
    printf("%s: called\n", __func__);
    ocall_getenv(env, envbuf, len);
    return envbuf;
}

void
perror(const char *m)
{
    ocall_print(m);
}

/*
 * system call
 */
int
open(const char *path, int flags)
{
    int	ret;
    ocall_open(path, flags, &ret);
    return ret;
}

int
close(int fd)
{
    int	ret;
    ocall_close(fd, &ret);
    return ret;
}

int
write(int fd, void *buf, size_t sz)
{
    size_t	rsz = 0;
    ocall_write(fd, buf, sz, &rsz);
    return rsz;
}

ssize_t
read(int fd, void *buf, size_t sz)
{
    ssize_t	rsz = 0;
    ocall_read(fd, buf, sz, &rsz);
    return rsz;
}

ssize_t
sendto(int, const void*, size_t, int, const struct sockaddr *, socklen_t)
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
lseek()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
closelog()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
openlog()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
__syslog_chk()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
getauxval()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
fstat()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
setbuf()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
__fread_alias()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
ferror()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
fclose()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
clearerr()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
__open_alias()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
fdopen()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
chmod()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}
int
fileno()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
__recvfrom_alias()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

/*
 * _Uelf64_valid_object
*/

/********************************************************************
 *
 */
/*
 * for C main arguments
 */
char	**
makeargv(int argc, int *argpos, char *buf)
{
    char	**argv = malloc(sizeof(char*)*(argc+1));
    int	i;
    for (i = 0; i < argc; i++) {
	argv[i] = &buf[argpos[i]];
    }
    argv[i] = NULL;
    return argv;
}

/*
 * Host machine may call this file
 */
sgx_status_t e_main(int argc, int *argpos, int blen, char *buf)
{
    char	**argv;
    size_t	faddr = 0;

    //ocall_print("Enclave called\n");
    argv = makeargv(argc, argpos, buf);

    //ocall_print("\t calling main routine\n");
    //printf("%s: testing printf\n", __func__);

    main(argc, argv);
    return SGX_SUCCESS;
}

/* functions for testing */
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
