#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>

int dflag;
int vflag;
int iteration;
int length;
int cn;

void
perf_init(int argc, char **argv)
{
    int		opt;

    while ((opt = getopt(argc, argv, "c:d:vi:l")) != -1) {
	switch (opt) {
	case 'c': /* core */
	    cn = atoi(optarg);
	    break;
	case 'd': /* debug */
	    dflag = atoi(optarg);
	    break;
	case 'v': /* verbose or verify */
	    vflag = 1;
	    break;
	case 'i': /* iteration */
	    iteration = atoi(optarg);
	    break;
	case 'l': /* length */
	    length = atoi(optarg);
	    break;
	}
    }
    optind = 0; /* reset getopt() library */
}

void
perf_showtime(int iteration, const char *msg,
	      struct timespec *ts_start, struct timespec *ts_end)
{
    double sec = ts_end->tv_sec - ts_start->tv_sec;
    double nsec = ts_end->tv_nsec - ts_start->tv_nsec;
    double usec;

    /* nsec accuracy -> msec */
    usec = ((double)sec*1000000 + (double)nsec/1000);
    usec /= (double)iteration;
    printf("%s: %.3f usec avg. of %d iteration\n",
	   msg, usec, iteration);
}

void
core_set(int core)
{
    int		i, rc, pid;
    cpu_set_t   mask;

    pid = getpid();
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    rc = sched_setaffinity(pid, sizeof(mask), &mask);
    if (rc < 0) {
	printf("Cannot set CPU affinity\n");
    }
    /* checking */
    CPU_ZERO(&mask);
    sched_getaffinity(pid, sizeof(cpu_set_t), &mask);
    for (i = 0; i < CPU_SETSIZE; i++) {
	if (CPU_ISSET(i, &mask)) {
	    printf("\tCORE#%d ", i);
	}
    }
    printf("\n");
}
