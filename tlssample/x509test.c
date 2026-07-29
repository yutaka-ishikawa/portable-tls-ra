/*
 * openssl x509 -in x509.der -inform DER -text -noout
 * openssl verify -CAfile x509.pem x509.der
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libsock.h"
#include "libmyssl.h"

int	dflag = 0;

int
main(int argc, char **argv)
{
    X509	*x509;
    EVP_PKEY	*pkey;
    int	rc = 0;

    rc = mysslra_x509(&x509, &pkey, NULL, NULL, NULL, 0);
    if (rc != 1) {
	return rc;
    }
    {	/* PEM file */
	FILE	*fp;
	if ((fp = fopen("x509.pem", "wb")) == NULL) {
	    fprintf(stderr, "Cannot create x509.pem\n");
	    return -1;
	}
	PEM_write_X509(fp, x509);
	fclose(fp);
    }
    {	/* DER file */
	FILE	*fp;
	if ((fp = fopen("x509.der", "wb")) == NULL) {
	    fprintf(stderr, "Cannot create x509.der\n");
	    return -1;
	}
	i2d_X509_fp(fp, x509);
	fclose(fp);
    }
    return 0;
}

/*
 * uint8_t	*der_x509 = NULL;
 * len = i2d_X509(x509, &der_x509);
 * OPENSSL_free(der_x509);
 */
