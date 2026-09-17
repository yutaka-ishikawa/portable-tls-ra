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
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>
#include <pthread.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include "libmeasurement.h"

#define LINE_SIZE       4096
#define PATH_SIZE       4096
#define HASH_SIZE       32
#define READ_SIZE       8192

/*
 * Remove leading and trailing white space.
 */
static char *
trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s))  s++;
    if (*s == '\0') return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

#if 0
/*
 * Remove the " (deleted)" suffix used by /proc/<pid>/maps.
 */
static void
remove_deleted_suffix(char *path)
{
    char *p;

    p = strstr(path, " (deleted)");
    if (p != NULL) *p = '\0';
}
#endif


/*
 * Return non-zero if the pathname looks like a shared library.
 * Examples:
 *     /usr/lib/x86_64-linux-gnu/libc.so.6
 *     /lib/x86_64-linux-gnu/libcrypto.so.3
 */
static int
is_shared_library(const char *path)
{
    if (path == NULL)  return 0;
    if (strstr(path, ".so") == NULL)  return 0;
    return 1;
}

/*
 * Check whether the pathname has already been registered.
 */
static int
path_exists(struct path_entry *head, const char *path)
{
    struct path_entry *p;

    for (p = head; p != NULL; p = p->next) {
        if (strcmp(p->path, path) == 0) return 1;
    }
    return 0;
}

/*
 * Add a pathname to the list.
 */
static int
add_path(struct path_entry **head, const char *path,
	 const unsigned char *dp, unsigned int dlen)
{
    struct path_entry *entry;

    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return -1;
    entry->path = strdup(path);
    memcpy(entry->digest, dp, dlen);
    if (entry->path == NULL) {
        free(entry);
        return -1;
    }

    entry->next = *head;
    *head = entry;

    return 0;
}

/*
 * Free the pathname list.
 */
void
free_paths(struct path_entry *head)
{
    struct path_entry *p;
    struct path_entry *next;

    for (p = head; p != NULL; p = next) {
        next = p->next;
        free(p->path);
        free(p);
    }
}


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
    if (fd > 0) close(fd);
    return 0;

err2:
    ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(ctx);
err1:
    if (cp) free(cp);
    if (fd > 0) close(fd);
    return result;
}

/*
 * Extract shared library digests from /proc/<pid>/maps.
 *  A return value is library count.
 */
int
sha256_libs(pid_t pid, struct path_entry **head)
{
    char	procfile[128];
    char	line[LINE_SIZE];
    FILE	*fp;
    int		count = 0;

    snprintf(procfile, sizeof(procfile), "/proc/%ld/maps", (long)pid);
    fp = fopen(procfile, "r");
    if (fp == NULL) {
        perror(procfile);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
	char	perms[8];
	char	dev[32];
	char	pathbuf[PATH_SIZE];
	char	*path;
	unsigned long start;
	unsigned long end;
	unsigned long offset;
	unsigned long inode;
	unsigned char dig[EVP_MAX_MD_SIZE];
	unsigned int  dlen;
	int	n;
	int pos = 0;
        /*
         * Read the fixed fields first.  %n gives the position where
         * the optional pathname starts.
         */
        n = sscanf(line, "%lx-%lx %7s %lx %31s %lu %n",
                   &start, &end, perms, &offset, dev, &inode, &pos);
        if (n < 6 || pos <= 0 || line[pos] == '\0') continue;
        path = trim(line + pos);
        /* Ignore anonymous mappings such as: [heap] [stack] [vdso] */
        if (*path == '\0' || *path == '[')  continue;

#if 0
        snprintf(pathbuf, sizeof(pathbuf), "%s", path);
        remove_deleted_suffix(pathbuf);
#endif
	/* getting real file path using virtual address */
	snprintf(pathbuf, sizeof(pathbuf),
		 "/proc/%ld/map_files/%lx-%lx", (long)pid, start, end);
	//printf("pathbuf = %s\n", pathbuf);

        if (!is_shared_library(pathbuf)) continue;
        if (path_exists(*head, pathbuf)) continue;
	if (sha256_file(pathbuf, dig, &dlen) != 0) {
            fprintf(stderr, "ERROR  %s\n", pathbuf);
            continue;
        }
        if (add_path(head, pathbuf, dig, dlen) != 0) {
            fprintf(stderr, "cannot allocate path entry\n");
            fclose(fp);
            return -1;
        }
	count++;
    }

    fclose(fp);
    return count;
}

int
sha256_pid(int pid, uint8_t *digest, unsigned int *digest_len,
	   char *cmdpath, size_t path_len)
{
    char	path[PATH_MAX+1];
    ssize_t	len;
    int	rc;
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    rc = sha256_file(path, digest, digest_len);
    if (rc < 0) goto err;
    if (cmdpath) {
	len = readlink(path, cmdpath, path_len - 1);
	if (len >= 0) {
	    cmdpath[len] = 0;
	}
    }
err:
    return rc;
}

#ifdef CMD_MEASURE
static void
dump(FILE *fp, const char *msg, const unsigned char *bf, int size)
{
    int	i;
    fprintf(fp, "%s", msg);
    for (i = 0; i < size; i++) {
	fprintf(fp, "%02x:", bf[i]);
    }
    fprintf(fp, "\n");
}

/*
 *	$ ./measure
 *	$ ./measure ./test_measurement
 *	$ ./measure -o digest.bin ./test_measurement
 *	$ ./measure -l ## for shared-library digests
 */
int
main(int argc, char **argv)
{
    uint8_t	digest[64];
    unsigned int dlen = sizeof(digest);
    int	opt;
    int	lflag = 0;
    int	fd = 0;
    char	*ofile = NULL;

    while((opt = getopt(argc, argv, "lo:")) != -1) {
	switch (opt) {
	case 'l': lflag = 1; break;
	case 'o': ofile = optarg; break;
	}
    }
    if (lflag) { /* digests of libraries */
	int	count;
	int	pid = getpid();
	struct path_entry *paths = NULL, *pa;
	count = sha256_libs(pid, &paths);
	if (count == 0) {
	    printf("No shared libraries\n");
	} else {
	    printf("%d shared libraries\n", count);
	    for (pa = paths; pa; pa = pa->next) {
		printf("%s\t", pa->path);
		dump(stdout, "", pa->digest, 32);
	    }
	}
    } else {
	if (optind < argc) {
	    if (sha256_file(argv[optind], digest, &dlen) < 0) {
		return -1;
	    }
	} else {
	    char	cmdpath[PATH_SIZE];
	    int pid = getpid();
	    sha256_pid(pid, digest, &dlen, cmdpath, PATH_SIZE);
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
	    dump(stderr, "digest: ", digest, dlen);
	}
	if (fd) close(fd);
    }
    return 0;
}
#endif /* LIBMEASUREMENT_TEST */
