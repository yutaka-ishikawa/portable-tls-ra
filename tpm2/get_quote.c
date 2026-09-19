#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "libquote.h"

#define NONCE_SIZE	32

int	vflag;
char	*quote_path = "./reg_quote.bin";

int
main(int argc, char **argv)
{
    uint8_t	nonce[NONCE_SIZE];
    int		nsize = NONCE_SIZE;
    uint8_t	pcrs[] = {0, 1, 2, 7, 10};
    int count = 5;
    struct tpm2_quote	t_quote;
    int	rc;
    size_t	sz;
    int	fd;

    memset(nonce, 0, NONCE_SIZE);
    rc = make_tpm2_quote(nonce, nsize,
			 TPM2_ALG_SHA256, pcrs, count, 0x81018001,
			 &t_quote);
    if (rc < 0) {
	goto ext;
    }
    fd = open(quote_path, O_CREAT|O_RDWR, 0666);
    if (fd < 0) {
	fprintf(stderr, "Cannot create quote file: %s\n", quote_path);
	goto ext;
    }
    sz = write(fd, t_quote.quote, t_quote.qsize);
    if (sz != t_quote.qsize) {
	fprintf(stderr, "Cannot save quote file: %s\n", quote_path);
	close(fd);
	goto ext;
    }
    close(fd);
ext:
    return rc;
}
