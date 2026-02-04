/* dummy */
typedef uint64_t FILE;
extern FILE	*stderr;

/* C functions */
extern int	printf(const char *fmt, ...);
extern int	fprintf(FILE *fp, const char *fmt, ...);
extern int	fputc(int ch, FILE*);
extern size_t	fwrite(const void *ptr, size_t sz, size_t nm, FILE *);
extern char	*getenv(const char *env);
extern void	perror(const char *m);

/* System calls */
extern int	close(int fd);
extern ssize_t	read(int fd, void *buf, size_t sz);

/* the following functions are dummy */
//extern ssize_t	sendto(int, const void*, size_t, int, const struct sockaddr *, socklen_t);
extern int	lseek();
extern int	closelog();
extern int	openlog();
extern int	__syslog_chk();
extern int	getauxval();
extern int	fstat();
extern int	setbuf();
extern int	__fread_alias();
extern int	ferror();
extern int	fclose();
extern int	clearerr();
extern int	__open_alias();
extern int	fdopen();
extern int	chmod();
extern int	fileno();
extern int	__recvfrom_alias();

#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100

#define SGX_DEBUG	if (sgx_dflag)
#define SGX_VFLAG	if (sgx_vflag)
