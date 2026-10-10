/*
 * TEE Host Call Library for PICA
 *    This module is linked with the host code.
 *
 */
#include <unistd.h>
#include <stdint.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include "error_check.h"
#include "libio.h"

void
myssl_errors()
{
    char	*buf;
    long	len;
    BIO		*bio = BIO_new(BIO_s_mem());

    if (bio == NULL) return;
    ERR_print_errors(bio);
    if ((len = BIO_get_mem_data(bio, &buf)) < 0) {
        fprintf(stderr, "%.*s", (int)len, buf);
    }
    BIO_free(bio);
}

/*
 * file manipulation
 */
#ifndef SGXENV
/* Host code */
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>

/* file_open for client code */
int
file_open(const char *path, int flag, int mode)
{
    int fd = open(path, flag, mode);
    return fd;
}

/* ocall_file_open is a host call service */
void
ocall_file_open(const char *path, int flag, int mode, int *fd)
{
    *fd = file_open(path, flag, mode);
}

/* file_read for client code */
size_t
file_read(int fd, void *buf, size_t rsz)
{
    size_t	sz = read(fd, buf, rsz);
    return sz;
}

/* ocall_file_read is a host call service */
void
ocall_file_read(int fd, void *buf, size_t rsz, size_t *read_sz)
{
    *read_sz = file_read(fd, buf, rsz);
}

/* file_write for client code */
size_t
file_write(int fd, void *buf, size_t wsz)
{
    size_t	sz = write(fd, buf, wsz);
    return sz;
}

/* ocall_file_write is a host call service */
void
ocall_file_write(int fd, void *buf, size_t wsz, size_t *written_sz)
{
    *written_sz = file_write(fd, buf, wsz);
}

/* file_lseek for client code */
int
file_lseek(int fd, long offset, int whence)
{
    int	rc = lseek(fd, offset, whence);
    return rc;
}

/* ocall_file_lseek is a host call service */
void
ocall_file_lseek(int fd, long offset, int whence, int *ret)
{
    *ret = file_lseek(fd, offset, whence);
}

/* file_close for client code */
int
file_close(int fd)
{
    return close(fd);
}

/* ocall_file_close is a host call service */
void
ocall_file_close(int fd, int *rc)
{
    *rc = file_close(fd);
}

/* file_chmod for client code */
int
file_chmod(const char *path, int mode)
{
    int	rc = chmod(path, mode);
    return rc;
}

/* ocall_file_chmod is a host call service */
void
ocall_file_chmod(const char *path, int mode, int *ret)
{
    *ret = file_chmod(path, mode);
}

/* file_read_close for client code */
size_t
file_read_close(int fd, uint8_t *buf,  size_t bufsz)
{
    size_t sz = read(fd, buf, bufsz);
    if (sz != bufsz) {
	printf("%s: Cannot read whole file (%ld != %ld)\n",
	       __func__, sz, bufsz);
    }
    close(fd);
    return sz;
}

/* ocall_file_fread_close is a host call service */
void
ocall_file_read_close(int fd, void *buf, size_t rsz, size_t *read_sz)
{
    *read_sz = file_read_close(fd, buf, rsz);
}

/*
 * file_read_close for client code
 *	read a whole file and close
 */
size_t
file_read_file(const char *path, void *buf,  size_t bufsz)
{
    size_t sz = 0;
    size_t	len;
    int	fd = open(path, O_RDONLY);

    if (fd < 0) {
	printf("%s: Cannot open file %s\n", __func__, path);
	goto err;
    }
    len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (len > bufsz) {
	printf("%s: Not enough buffer size, %ld > %ld.\n", __func__, len, bufsz);
	goto err;
    }
    sz = read(fd, buf, len);
    if (sz != len) {
	printf("%s: Cannot read whole file (%ld != %ld)\n", __func__, sz, bufsz);
    }
    close(fd);
err:
    return sz;
}

/* ocall_file_fread_close is a host call service */
void
ocall_file_read_file(const char *path, uint8_t *buf,  size_t rsz, size_t *read_sz)
{
    *read_sz = file_read_file(path, buf, rsz);
}

/* file_size for client code */
int
file_size(const char *path, size_t *sz)
{
    off_t	off;
    int	fd;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
	printf("%s: Cannot open file %s\n", __func__, path);
	*sz = 0; goto err;
    }
    off = lseek(fd, 0, SEEK_END);
    *sz = (size_t) off;
    lseek(fd, 0, SEEK_SET);
err:
    return fd;
}

/* ocall_file_size is a host call service */
void
ocall_file_size(const char *path, size_t *sz, int *fd)
{
    *fd = file_size(path, sz);
}

/*
 * Non-TEE: no file_seal_write function available.
 */
int
file_seal_write(int fd, void *buf, size_t wsz)
{
    size_t	sz;
    int	rc;
    fprintf(stderr, "%s: Must consider to implement this function in Non-TEE\n", __func__);
    sz = file_write(fd, buf, wsz);
    rc = (sz == wsz);
    return rc;
}

/*
 * Non-TEE: no file_seal_read_close function available.
 */
size_t
file_seal_read_close(int fd, void **o_buf, size_t rsz)
{
    fprintf(stderr, "%s: Must consider to implement this function in Non-TEE\n", __func__);
    *o_buf = malloc(rsz);
    if (*o_buf == NULL) {
	fprintf(stderr, "%s: Cannot allocate memory (%ld)\n", __func__, rsz);
	return 0;
    }
    rsz = file_read_close(fd, *o_buf, rsz);
    return rsz;
}

#else
/*-------------------------------------------------------------------------
 * SGXENV
 *-------------------------------------------------------------------------*/
#include "pica_t.h"
#include "pica_sgxenv.h"
#include <sgx_tseal.h>

/* TEE codes: SGX Enclave */
int
file_open(const char *path, int flag, int mode)
{
    int	fd;
    ocall_file_open(path, flag, mode, &fd);
    return fd;
}

size_t
file_write(int fd, void *buf, size_t wsz)
{
    size_t	written_sz;
    ocall_file_write(fd, buf, wsz, &written_sz);
    return written_sz;
}

size_t
file_read_close(int fd, uint8_t *buf,  size_t bufsz)
{
    size_t	read_sz;
    ocall_file_read_close(fd, buf, bufsz, &read_sz);
    return read_sz;
}

int
file_close(int fd)
{
    int	rc;
    ocall_file_close(fd, &rc);
    return rc;
}

size_t
file_read_file(const char *path, void *buf, size_t rsz)
{
    size_t	read_sz;

    ocall_file_read_file(path, buf, rsz, &read_sz);
    return read_sz;
}

int
file_size(const char *path, size_t *sz)
{
    int	fd;
    ocall_file_size(path, sz, &fd);
    return fd;
}

/*
 * TEE (Intel Enclave): file_seal_write function
 */
int
file_seal_write(int fd, void *buf, size_t wsz)
{
    uint32_t	enclen;
    sgx_sealed_data_t 	*encbufp;
    sgx_status_t  st;
    int	rc = -1;

    enclen = sgx_calc_sealed_data_size(0, wsz);
    encbufp = malloc(enclen);
    if(encbufp == NULL) goto err;
    st = sgx_seal_data(0, NULL, wsz, buf, enclen, encbufp);
    if (st != SGX_SUCCESS) {
	fprintf(stderr, "%s: sgx_seal_data error: 0x%x\n", __func__, st);
	goto err;
    }
    wsz = file_write(fd, encbufp, enclen);
    rc = (wsz == enclen);
    free(encbufp);
err:
    return rc;
}

/*
 * TEE (Intel Enclave): file_seal_read_close function available.
 */
size_t
file_seal_read_close(int fd, void **o_buf, size_t enc_sz)
{
    uint8_t	*encp, *decp;
    size_t	rsz;
    uint32_t	dec_sz = 0;
    sgx_status_t st;
    
    encp = malloc(enc_sz);
    if (encp == NULL) {
	fprintf(stderr, "%s: Cannot allocate memory (%ld)\n", __func__, enc_sz);
	goto err;
    }
    rsz = file_read_close(fd, encp, enc_sz);
    if (rsz != enc_sz) {
	fprintf(stderr, "%s: cannot read\n", __func__);
	rsz = 0; *o_buf = NULL;
	goto err0;
    }
    dec_sz = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)encp);
    decp = malloc(dec_sz);
    if (decp == NULL) {
	fprintf(stderr, "%s: Cannot allocate memory (%d)\n", __func__, dec_sz);
	dec_sz = 0; *o_buf = NULL;
	goto err0;
    }
    st = sgx_unseal_data((const sgx_sealed_data_t *) encp, NULL, 0, decp, &dec_sz);
    if (st != SGX_SUCCESS) {
	fprintf(stderr, "%s: sgx_seal_data error: 0x%x\n", __func__, st);
	goto err;
    }
    *o_buf = decp;
err0:
    free(encp);
err:
    return dec_sz;
}

#endif /* ~SGXENV */

/*****************************************************************************
 * C library compatibility
 ****************************************************************************/
#ifdef SGXENV
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

FILE	*stdout;
FILE	*stderr;

int
__printf_chk(int flag, const char *fmt, ...)
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
    return len;
}

int
__fprintf_chk(FILE *stream, int flag, const char *fmt, ...)
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
    return len;
}

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
    return len;
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
    return len;
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

/*
 * system call
 */
int
open(const char *path, int flags, int mode)
{
    int	ret;
    ocall_file_open(path, flags, mode, &ret);
    return ret;
}

int
close(int fd)
{
    int	ret;
    ocall_file_close(fd, &ret);
    return ret;
}

int
write(int fd, void *buf, size_t sz)
{
    size_t	rsz = 0;
    ocall_file_write(fd, buf, sz, &rsz);
    return rsz;
}

ssize_t
read(int fd, void *buf, size_t sz)
{
    size_t	rsz = 0;
    ocall_file_read(fd, buf, sz, &rsz);
    return rsz;
}

struct sockaddr;
ssize_t
sendto(int, const void*, size_t, int, const struct sockaddr *, int)
{
    fprintf(stderr, "%s: called. not yet implmented\n", __func__);
    return -1;
}

off_t
lseek(int fd, off_t offset, int whence)
{
    off_t	pos;
    ocall_file_lseek(fd, offset, whence, &pos);
    return pos;
}

int
closelog()
{
    fprintf(stderr, "%s: called. not implemented.\n", __func__);
    return -1;
}

int
openlog(const char *ident, int option, int facility)
{
    fprintf(stderr, "%s: called. not yet implemented.\n", __func__);
    return -1;
}

int
__syslog_chk()
{
    fprintf(stderr, "%s: called\n", __func__);
    return -1;
}

int
getauxval(unsigned long type)
{
    fprintf(stderr, "%s: type = 0x%lx called. not yet implemented\n", __func__, type);
    return -1;
}

struct stat;
int
fstat(int fd, struct stat *statbuf)
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return -1;
}

int
setbuf(FILE *stream, char *restrict buf)
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
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
fclose(FILE *stream)
{
    fprintf(stderr, "%s: called. not implemented.\n", __func__);
    return -1;
}

int
clearerr(FILE *stream)
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return -1;
}

int
__open_alias()
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return -1;
}

FILE *
fdopen(const char *restrict pathname, const char *restrict mode)
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return 0;
}

int
chmod(const char *pathname, int mode)
{
    int	ret;
    ocall_file_chmod(pathname, mode, &ret);
    return ret;
}

int
fileno(FILE *stream)
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return -1;
}

int
__recvfrom_alias()
{
    fprintf(stderr, "%s: called. not implemented\n", __func__);
    return -1;
}

char *
getenv(const char *env)
{
    static char	envbuf[1024];
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

int
putchar(int c)
{
    int rc;
    ocall_putchar(c, &rc);
    return rc;
}

int
puts(const char *s)
{
    int rc;
    ocall_puts(s, &rc);
    return rc;
}

#else
/* Host code */
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

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

void ocall_print(const char *s)
{
    printf("%s", s);
}

void ocall_putchar(int s, int *ret)
{
    int	rc = putchar(s);
    *ret = rc;
}

void ocall_puts(const char *s)
{
    puts(s);
}

void ocall_putn(const char *s, int len, size_t *wlen)
{
    char	ch = '\n';
    size_t	sz;
    sz = fwrite(s, len, 1, stdout);
    fwrite(&ch, 1, 1, stdout);
    sz++;
    *wlen = sz;
}

/*-----------------------------------------------------------------------------
 * Host codes for sgxssl
 *-----------------------------------------------------------------------------*/
ssize_t
u_sgxssl_write(int fd, const void* buf, size_t n)
{
    ssize_t ret;
    ret = write(fd, buf, n);
    return ret;
}
	
ssize_t
u_sgxssl_read(int fd, void* buf, size_t count)
{
    ssize_t ret;
    ret = read(fd, buf, count);
    return ret;
}
	
int
u_sgxssl_close(int fd)
{
    int ret;
    ret = close(fd) ;
    return ret;
}

int
u_sgxssl_open(const char *filename, int flags)
{
    if (filename == NULL) return -1;
    int ret = open(filename, flags);
    return ret;
}

#include <sys/timeb.h>
#include <time.h>
void
u_sgxssl_ftime(void * timeptr, uint32_t timeb_len)
{
    struct timeb *tb = (struct timeb *)timeptr;
    struct timespec ts;
    if (timeptr == NULL)  return;
    if (timeb_len < sizeof(struct timeb))  return;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)       return;
    tb->time = ts.tv_sec;
    tb->millitm = (unsigned short)(ts.tv_nsec / 1000000L);
    tb->timezone = 0;
    tb->dstflag = 0;
}

void u_sgxssl_usleep(int micro_seconds)
{
    usleep(micro_seconds);
}

#endif /* SGXENV */

static void
tss_error(const char *cmd, TSS2_RC rc)
{
    const char	*message = Tss2_RC_Decode(rc);
    fprintf(stderr, "%s failed: 0x%x (%s)\n",  cmd, rc,
	    (message == NULL) ? "unknown TSS2 error" : message);
}

/*
 *
 */
#define PEM_SIZE	(32*1024)
int
read_pubkey(const char *fname, EVP_PKEY **ak_pubkey)
{
    char	*buf = malloc(PEM_SIZE);
    size_t	len;
    BIO		*bio = NULL;
    int	rc = -1;

    len = file_read_file(fname, buf, PEM_SIZE);
    if (len == 0) {
	goto err;
    }
    bio = BIO_new_mem_buf(buf, len);
    *ak_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (ak_pubkey == NULL) {
	fprintf(stderr, "The %s file is not a PEM file.\n", fname);
	goto err;
    }
    rc = 0;
err:
    return rc;
}

int
read_tpm2attest(const char *fname, TPMS_ATTEST *reg_atst)
{
    int	rc = -1;
    int	fd;
    size_t	sz, rsz;
    uint8_t	*ser_qt;
    size_t	off = 0;

    fd = file_size(fname, &sz);
    if (sz <= 0) {
	fprintf(stderr, "Cannot open a file of valid PCRs: %s\n", fname);
	goto err;
    }
    ser_qt = malloc(sz);
    rsz = file_read_close(fd, ser_qt, sz);
    if (rsz != sz) {
	fprintf(stderr, "Cannot read the entire data of %s file.\n", fname);
	goto err;
    }
    off = 0;
    TPM2_CALL(err, rc,
	      Tss2_MU_TPMS_ATTEST_Unmarshal(ser_qt, sz, &off, reg_atst));
    free(ser_qt);
    if (reg_atst->type != TPM2_ST_ATTEST_QUOTE) {
	fprintf(stderr, "%s: The %s file is not a TPM2 quote\n", __func__, fname);
	goto err;
    }
    rc = 0;
err:
    return rc;
}
