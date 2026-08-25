CFLAGS = -MMD -Wall -g -O2
INCL = 
LIBS =  -ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc -lcrypto -lcbor
SRCS  = $(wildcard *.c)
OBJS  = $(SRCS_COMMON:.c=.o)
DEPS  = $(SRCS_COMMON:.c=.d)

MYLIBS = libquote.o libsock.o libmeasurement.o
MYCMDS = tpmdaemon test_tpmd test_quote test_libsock measure

#all: quote_esys libquote.o test_quote
all: $(MYLIBS) $(MYCMDS)
tpmdaemon: tpmdaemon.o libquote.o libsock.o libmeasurement.o
	cc $(CFLAGS) -o $@ $^ $(LIBS)
test_tpmd: test_tpmd.o libquote.o libsock.o libmeasurement.o
	cc $(CFLAGS) -o $@ $^ $(LIBS)
test_quote: libquote.c
	cc $(CFLAGS) -DLIBQUOTE_TEST -o $@ $^ $(LIBS)
test_libsock: libsock.c libsock.h
	cc $(CFLAGS) -DLIBSOCK_TEST -o $@ libsock.c
measure: libmeasurement.c
	cc $(CFLAGS) -DCMD_MEASURE -o $@ $^ -lcrypto
quote_esys: quote_esys.c
	cc $(CFLAGS) -o $@ $^ $(LIBS)

run-daemon:
	sudo ./tpmdaemon /tmp/sock-tpmd-daemon
clean:
	rm -f  $(MYLIBS) $(MYCMDS)
depend:

-include $(DEPS)
