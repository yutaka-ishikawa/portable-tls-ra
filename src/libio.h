/*
 *
 */
#ifdef SGXENV
#include "pica_sgxenv.h"
#else
#include <stdio.h>
#endif

extern int	file_open(const char *path, int flag, int mode);
extern size_t	file_write(int fd, void *buf, size_t wsz);
extern size_t	file_read(int fd, void *buf, size_t rsz);
extern int	file_lseek(int fd, long offset, int where);
extern int	file_close(int fd);
extern int	file_chmod(const char *path, int mode);
/**/
extern size_t	file_read_close(int fd, uint8_t *buf,  size_t bufsz);
extern size_t	file_read_file(const char *path, void *buf, size_t sz);
extern int	file_size(const char *path, size_t *sz);
/**/
extern void	myssl_errors();

/*
 * For Attestation
 */
extern int	read_pubkey(const char *path, EVP_PKEY **ak_pubkey);
extern int	read_tpm2attest(const char *fname, TPMS_ATTEST *reg_atst);
