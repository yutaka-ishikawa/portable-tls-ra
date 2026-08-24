extern int	sha256_file(const char *path,
			    uint8_t *digest, unsigned int *digest_len);
extern int	sha256_pid(int pid, uint8_t *digest, unsigned int *digest_len);
