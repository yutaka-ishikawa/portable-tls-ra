PROGS=	perf_openclose
all: $(PROGS)

perf_openclose: perf_openclose.o perflib.o
	cc -O2 -o $@ $^
perflib.o: perflib.c
	cc -O2 -c perflib.c

run-open:
	sh ./run-perf.sh ./perf_openclose ../data/MEASURE-OPENCLOSE-normal.txt
run-open-pessh:
	sh ./run-perf.sh ./perf_openclose ../data/MEASURE-OPENCLOSE-pessh.txt

run-compile:
	sh ./run-conf-make.sh ../data/MEASURE-COMPILE-normal.txt
run-compile-pessh:
	sh ./run-conf-make.sh ../data/MEASURE-COMPILE-pessh.txt
