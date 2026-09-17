#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include "perflib.h"

extern int	iteration;

int
main(int argc, char **argv)
{
    unsigned    cpu, node;
    int	i, pid;
    PERF_DECL(ts_start, ts_end);

    iteration = DEFAULT_ITER_COUNT;
    pid = getpid();
    
    PERF_START(&ts_start);
    for (i = 0; i < iteration; i++) {
	pid = getpid();
    }
    PERF_END(&ts_end);
    perf_showtime(iteration, "getpid", &ts_start, &ts_end);

    PERF_START(&ts_start);
    for (i = 0; i < iteration; i++) {
	int	fd = open(argv[0], O_RDONLY);
	if (fd < 0) goto err_ext;
	close(fd);
    }
    PERF_END(&ts_end);
    perf_showtime(iteration, "open&close", &ts_start, &ts_end);
    return 0;
err_ext:
    return -1;
}
