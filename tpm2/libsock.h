#ifndef _LIBSOCK_H
#define _LIBSOCK_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>	
#include <unistd.h>

extern int	sock_listen(const char *path);
extern int	sock_connect(const char *path);
extern int	sock_client_pid(int con);
extern int	sock_send(int con, void *buf, size_t size);
extern int	sock_recv(int con, void *buf, size_t size);

#endif
