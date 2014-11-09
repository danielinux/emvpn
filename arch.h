#include <stdint.h>
#include <string.h>


#if defined __IAR_SYSTEMS_ICC__ || defined ATOP
#   define DEF_PACKED_STRUCT __packed struct
#   define DEF_PACKED_UNION  __packed union
#else
#   define DEF_PACKED_STRUCT struct __attribute__((packed))
#   define DEF_PACKED_UNION  union /* No need to pack unions in GCC */
#endif

#ifdef __linux__
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

typedef int VPNSOCKET;
#define vpn_alloc(x) calloc(1, x);
#define vpn_free(x) free(x);

#define vpn_socket_err(x) ((x) < 0)

static VPNSOCKET vpn_socket_open(uint16_t ip_ver, void *addr, uint16_t port)
{
    struct sockaddr_storage _s_addr;
    int sock = -1;
    int socksize;
    memset(&_s_addr, 0, sizeof(_s_addr));
    errno = EINVAL;

    if (ip_ver == 4) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *) &_s_addr;
        socksize = sizeof(struct in_addr);
        s_addr->sin_family = AF_INET;
        memcpy(&s_addr->sin_addr.s_addr, addr, sizeof(struct in_addr));
        s_addr->sin_port = htons(port);
        sock = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (ip_ver == 6) {
        struct sockaddr_in *s_addr = (struct sockaddr_in6 *) &_s_addr;
        socksize = sizeof(struct in_addr6);
        s_addr->sin6_family = AF_INET6;
        memcpy(&s_addr->sin6_addr, addr, sizeof(struct in_addr));
        s_addr->sin6_port = htons(port);
        sock = socket(AF_INET6, SOCK_DGRAM, 0);
    }

    if (sock < 0)
        return sock;
    if (bind(sock, (struct sockaddr *)_s_addr, socksize) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

#endif
