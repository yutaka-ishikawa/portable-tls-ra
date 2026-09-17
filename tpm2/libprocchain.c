/*
 * libprocchain.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include "libprocchain.h"

#define PATH_SIZE       1024
#define LINE_SIZE       4096
#define CMDLINE_SIZE    8192

/*
 * Read the parent PID from /proc/<pid>/status.
 */
int
cred_pid(pid_t pid, pid_t *ppid, uid_t *ruid, uid_t *rgid,
	 uid_t *euid, uid_t *egid, uid_t *suid, uid_t *sgid)
{
    char path[PATH_SIZE];
    char line[LINE_SIZE];
    FILE *fp;
    int  pass = 0;

    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    fp = fopen(path, "r");
    if (fp == NULL)  return -1;
    *ppid = *ruid = *euid = *suid = *rgid = *egid = *sgid = -1;
    while (fgets(line, sizeof(line), fp) != NULL && pass < 3) {
        if (strncmp(line, "PPid:", 5) == 0) {
            if (sscanf(line + 5, "%d", ppid) != 1) *ppid = -1;
	    pass++;
        } else if (strncmp(line, "Uid:", 4) == 0) {
	    if (sscanf(line + 4, "%d %d %d",
		       ruid, euid, suid) != 3) {
		*ruid = *euid = *suid = -1;
	    }
	    pass++;
	} else if (strncmp(line, "Gid:", 4) == 0) {
	    if (sscanf(line + 4, "%d %d %d",
		       rgid, egid, sgid) != 3) {
		*rgid = *egid = *sgid = -1;
	    }
	    pass++;
	}
    }
    fclose(fp);
    return 0;
}


/*
 * get command path using /proc/<pid>/exe.
 */
static int
get_cmdpath(pid_t pid, char *buf, size_t buflen)
{
    char	path[PATH_SIZE];
    ssize_t	len;

    if (buf == NULL || buflen == 0) return 0;
    snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    len = readlink(path, buf, buflen - 1);
    if (len >= 0) {
	buf[len] = '\0';
    }
    return len;
}

/*
 * Read /proc/<pid>/cmdline.
 *
 * /proc/<pid>/cmdline contains NUL-separated arguments.
 * Convert the NUL characters into spaces for printing.
 */
static int
get_cmdline(pid_t pid, char *buf, size_t buflen)
{
    char	path[PATH_SIZE];
    FILE	*fp = NULL;
    size_t	len = 0;
    size_t	i;

    if (buf == NULL || buflen == 0) goto err;
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid);
    fp = fopen(path, "rb");
    if (fp == NULL) goto err;

    len = fread(buf, 1, buflen - 1, fp);
    if (len == 0) goto err;
    buf[len] = '\0';
    /*
     * Arguments in cmdline are separated by NUL characters.
     */
    for (i = 0; i < len; i++) {
        if (buf[i] == '\0')  buf[i] = ' ';
    }
    /*
     * Remove trailing spaces.
     */
    for (i = len; i > 0 && buf[i - 1] == ' '; --i) {
	buf[i - 1] = '\0';
    }
err:
    if (fp) fclose(fp);
    return len;
}

/*
 * Read /proc/<pid>/comm.
 *
 * This is used as a fallback when cmdline is empty, for example
 * for kernel threads.
 */
static int
get_comm(pid_t pid, char *buf, size_t buflen)
{
    char path[PATH_SIZE];
    FILE *fp;
    size_t len;

    if (buf == NULL || buflen == 0) return -1;

    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    fp = fopen(path, "r");
    if (fp == NULL) return -1;

    if (fgets(buf, buflen, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    return 0;
}

#ifdef LIBPROCCHAIN_TEST
/*
 * Print spaces according to the process-tree depth.
 */
static void
print_indent(int depth)
{
    int i;

    for (i = 0; i < depth; i++)  printf("    ");
}

/*
 * Print the command executed by a process.
 */
static void
print_process(pid_t pid, int depth)
{
    char cmdline[CMDLINE_SIZE];
    char cmdpath[PATH_SIZE];

    print_indent(depth);
    if (get_cmdline(pid, cmdline, sizeof(cmdline)) > 0) {
	printf("pid=%ld ", (long)pid);
        printf("%s\t", cmdline);
    }
    if (get_cmdpath(pid, cmdpath, sizeof(cmdpath)) > 0) {
        printf("cmdpath: %s\n", cmdpath);
        return;
    }
    if (get_comm(pid, cmdline, sizeof(cmdline)) == 0) {
        printf("[%s]\n", cmdline);
        return;
    } else {
	printf("\n");
    }

    printf("<unknown>\n");
}

/*
 * Find processes whose PPid is equal to parent_pid.
 * The function scans all numeric directories under /proc and checks
 * the PPid field in each /proc/<pid>/status file.
 * It recursively prints all descendants.
 */
static void
print_parent(pid_t pid, int depth)
{
    pid_t	ppid;
    uid_t	ruid, rgid, euid, egid, suid, sgid;

    /* see man 5 proc_pid_status */
    cred_pid(pid, &ppid, &ruid, &rgid, &euid, &egid, &suid, &sgid);

    if (ppid == (pid_t)-1) return;
    print_process(ppid, depth);
    /*
     * Recursively process descendants.
     */
    if (ppid != 1) {
	print_parent(ppid, depth + 1);
    }
}

int
main(int argc, char **argv)
{
    char *end;
    long value;
    pid_t pid;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }

    value = strtol(argv[1], &end, 10);

    if (*argv[1] == '\0' ||
        *end != '\0' ||
        value <= 0) {
        fprintf(stderr, "invalid pid: %s\n", argv[1]);
        return 1;
    }

    pid = (pid_t)value;

    /*
     * Print the specified process itself first.
     */
    print_process(pid, 0);

    /*
     * Print all descendant processes.
     */
    print_parent(pid, 1);

    return 0;
}
#endif /* LIBPROCCHAIN_TEST */
