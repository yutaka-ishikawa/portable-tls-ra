extern int	sock_connect_daemon(const char *dpath);
extern int	sock_connect(uint32_t ip, uint16_t port);
extern int	sock_serveropen(uint32_t ip, uint16_t port);
extern int	sock_accept(int sock);
extern int	sock_client_pid(int sock);
extern int	sock_send(int sock, void *buf, size_t size);
extern int	sock_recv(int sock, void *buf, size_t size);
