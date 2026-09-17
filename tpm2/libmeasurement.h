struct path_entry {
    char		*path;
    uint8_t		digest[64];
    struct path_entry	*next;
};

extern int	sha256_file(const char *path,
			    uint8_t *digest, unsigned int *digest_len);
extern int	sha256_pid(int pid, uint8_t *digest, unsigned int *digest_len,
			   char *cmdpath, size_t path_len);
extern int	sha256_libs(pid_t pid, struct path_entry **head);
void		free_paths(struct path_entry *head);
