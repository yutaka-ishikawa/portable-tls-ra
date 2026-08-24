/*
 * measurement
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>
#include <pthread.h>

#include <openssl/err.h>
#include <openssl/evp.h>

int
sha256_file(const char *path, uint8_t *digest, unsigned int *digest_len)
{
    struct stat		sbuf;
    unsigned char	*cp  = NULL;
    EVP_MD_CTX		*ctx = NULL;
    int			fd = -1;
    int result = -1;

    if ((fd = open(path, O_RDONLY)) < 0) {
	perror("open");
	goto err1;
    }
    if (fstat(fd, &sbuf) < 0) {
	perror("fstat");
	goto err1;
    }
    if ((cp = malloc(sbuf.st_size)) == NULL) {
	fprintf(stderr, "Cannot allocate memory. size=%ld\n", sbuf.st_size);
	goto err1;
    }
    if (read(fd, cp, sbuf.st_size) < sbuf.st_size) {
	fprintf(stderr, "Cannot read whole file %s\n", path);
	perror("read");
	goto err1;
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        goto err2;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto err2;
    }
    if (EVP_DigestUpdate(ctx, cp, sbuf.st_size) != 1) {
	goto err2;
    }
    if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
        goto err2;
    }
    return 0;

err2:
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
err1:
    if (cp) free(cp);
    if (fd > 0) close(fd);
    return result;
}

int
sha256_pid(int pid, uint8_t *digest, unsigned int *digest_len)
{
    char	path[PATH_MAX+1];
    int	rc;
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    rc = sha256_file(path, digest, digest_len);
    return rc;
}

#ifdef CMD_MEASURE
static void
dump(const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(stderr, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(stderr, "%02x:", bf[i]);
    }
    fprintf(stderr, "\n");
}

/*
 *	$ ./measure
 *	$ ./measure ./test_measurement
 *	$ ./measure -o digest.bin ./test_measurement
 */
int
main(int argc, char **argv)
{
    uint8_t	digest[64];
    unsigned int dlen = sizeof(digest);
    int	opt;
    int	fd = 0;
    char	*ofile = NULL;

    while((opt = getopt(argc, argv, "o:")) != -1) {
	switch (opt) {
	case 'o': ofile = optarg; break;
	}
    }
    if (optind < argc) {
	sha256_file(argv[optind], digest, &dlen);
    } else {
	int pid = getpid();
	sha256_pid(pid, digest, &dlen);
    }
    if (ofile && (fd = open(ofile, O_CREAT|O_RDWR, 0666)) > 0) {
	size_t	wsz;
	wsz = write(fd, digest, dlen);
	if (wsz != dlen) {
	    printf("write data is short (%ld < %d)\n", wsz, dlen);
	    perror("write error");
	}
	printf("%d Byte Digest is stored in %s\n", dlen, ofile);
    } else {
	dump("digest: ", digest, dlen);
    }
    if (fd) close(fd);
    return 0;
}
#endif /* LIBMEASUREMENT_TEST */
