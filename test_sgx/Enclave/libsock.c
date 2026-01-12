#include "Enclave_t.h"

int
sock_serveropen(uint32_t ip, uint16_t port)
{
    int	rc;
    ocall_sock_serveropen(ip, port, &rc);
    return rc;
}

int
sock_accept(int sock)
{
    int	rc;
    ocall_sock_accept(sock, &rc);
    return rc;
}

