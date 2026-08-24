CFLAGS = -MMD -Wall -g -O2
INCL = 
LIBS =  -ltss2-mu -ltss2-esys -ltss2-tctildr -ltss2-rc -lcrypto
SRCS  = $(wildcard *.c)
OBJS  = $(SRCS_COMMON:.c=.o)
DEPS  = $(SRCS_COMMON:.c=.d)

#all: quote_esys libquote.o test_quote
all: libquote.o test_quote libmeasurement.o measure
test_quote: libquote.c
	cc $(CFLAGS) -DLIBQUOTE_TEST -o $@ $^ $(LIBS)
measure: libmeasurement.c
	cc $(CFLAGS) -DCMD_MEASURE -o $@ $^ -lcrypto
quote_esys: quote_esys.c
	cc $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm quote_esys libquote.o test_quote
depend:

-include $(DEPS)
