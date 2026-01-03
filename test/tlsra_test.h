#include <arpa/inet.h>

#define DEFAULT_TCP_PORT	1100
#define DEFAULT_COUNT	1
#define DEFAULT_SIZE	1024
#define BUF_SIZE	1024

#define VERBOSE if (vflag)
#define VERYFY if (Vflag)
#define DEBUG if (dflag)

#define SYS_CALL0(label, val, sysname, lib)	\
do {				\
    val = lib;			\
    if (val != 0) {		\
    	perror(sysname);	\
	goto label;		\
    }				\
} while(0)

extern int	sock_serveropen(uint32_t ip, uint16_t port);
extern int	sock_accept(int socket);
extern int	sock_connect(uint32_t ip, uint16_t port);
extern uint32_t	str2ip(char *str);
extern char	*ipaddr(uint32_t);
extern void	combuf_init(unsigned char *, int);
extern void	combuf_vryfy(unsigned char *, int);
extern void	dump(const char *msg, const unsigned char *, int);
extern void	myssl_shutdown(SSL_CTX *ctx, SSL *ssl);
