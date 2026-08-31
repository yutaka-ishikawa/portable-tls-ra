CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

TARGET = echo_host

.PHONY: all clean

all: $(TARGET)

$(TARGET): echo_host.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
