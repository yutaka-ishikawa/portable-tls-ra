extern void	perf_showtime(int iteration, const char *msg,
			      struct timespec *ts, struct timespec *te);
extern void	perf_init(int argc, char **argv);
extern void	core_set(int);

#define DEFAULT_ITER_COUNT      1000

#define PERF_DECL(ts, te) struct timespec     ts, te

#define PERF_START(ts)			\
do {						\
    clock_gettime(CLOCK_MONOTONIC, (ts));	\
} while (0)

#define PERF_END(te)			\
do {						\
    clock_gettime(CLOCK_MONOTONIC, (te));	\
} while (0)
