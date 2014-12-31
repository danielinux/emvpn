#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libevquick.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include "emvpn.h"

void *posix_alloc(int x){
   return calloc(1, x);
}

void posix_free(void *x) {
    free(x);
}

uint16_t posix_ntohs(uint16_t x)
{
    return ntohs(x);
}

uint16_t posix_htons(uint16_t x)
{
    return htons(x);
}

uint32_t posix_ntohl(uint32_t x)
{
    return ntohl(x);
}

uint32_t posix_htohl(uint32_t x)
{
    return htonl(x);
}

int posix_socket_send(struct emvpn_socket *v, void *pkt, int len)
{
    struct sockaddr_storage _s_addr;
    int socksize;

    memset(&_s_addr, 0, sizeof(struct sockaddr_storage));
    if (v->conn < 0)
        return -1;

    if (v->ep_ipver == 6) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *) &_s_addr;
        socksize = sizeof(struct sockaddr_in6);
        s_addr->sin6_family = AF_INET6;
        memcpy(&s_addr->sin6_addr, v->ep_addr, sizeof(struct in6_addr));
        s_addr->sin6_port = v->ep_port;
    } else if (v->ep_ipver == 4) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *) &_s_addr;
        socksize = sizeof(struct sockaddr_in);
        s_addr->sin_family = AF_INET;
        memcpy(&s_addr->sin_addr, v->ep_addr, sizeof(struct in_addr));
        s_addr->sin_port = v->ep_port;
    } else return -1;

    return sendto(v->conn, pkt, len, 0, (struct sockaddr *)&_s_addr, socksize);
}

int posix_socket_recvfrom(struct emvpn_socket *v, void *pkt, int len, uint16_t *family, void *addr, uint16_t *port)
{
    struct sockaddr_storage _s_addr;
    int ret;
    unsigned int socksize = sizeof(struct sockaddr_storage);

    ret = recvfrom(v->conn, pkt, len, 0, (struct sockaddr *) &_s_addr, &socksize);
    if (ret < 0)
        return ret;
    if (socksize == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *) &_s_addr;
        memcpy(addr, &s_addr->sin_addr.s_addr, 4);
        *port = ntohs(s_addr->sin_port);
        *family = 4;
    } else if (socksize == sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *) &_s_addr;
        memcpy(addr, &s_addr->sin6_addr, 16);
        *port = ntohs(s_addr->sin6_port);
        *family = 6;
    } else {
        return -1;
    }
    return ret;
}

int posix_socket_connect(struct emvpn_socket *v)
{
    struct sockaddr_storage _s_addr;
    memset(&_s_addr, 0, sizeof(_s_addr));
    errno = EINVAL;

    if (v->ep_ipver == 4) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *) &_s_addr;
//        socksize = sizeof(struct in_addr);
        s_addr->sin_family = AF_INET;
        memcpy(&s_addr->sin_addr.s_addr, v->ep_addr, sizeof(struct in_addr));
        s_addr->sin_port = htons(v->ep_port);
        v->conn = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (v->ep_ipver == 6) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *) &_s_addr;
//        socksize = sizeof(struct in6_addr);
        s_addr->sin6_family = AF_INET6;
        memcpy(&s_addr->sin6_addr, v->ep_addr, sizeof(struct in6_addr));
        s_addr->sin6_port = htons(v->ep_port);
        v->conn = socket(AF_INET6, SOCK_DGRAM, 0);
    }

    return v->conn;
    /*
    if (bind(sock, (struct sockaddr *) &_s_addr, socksize) < 0) {
        close(sock);
        return -1;
    }
    */
}

int posix_socket_listen(struct emvpn_socket *v, uint16_t ip_ver, void *addr, uint16_t port)
{

    struct sockaddr_storage _s_addr;
    unsigned long socksize = 0;
    memset(&_s_addr, 0, sizeof(_s_addr));
    errno = EINVAL;


    if (ip_ver == 4) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *) &_s_addr;
        socksize = sizeof(struct sockaddr_in);
        s_addr->sin_family = AF_INET;
        memcpy(&s_addr->sin_addr.s_addr, addr, sizeof(struct in_addr));
        s_addr->sin_port = htons(port);
        v->conn = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (ip_ver == 6) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *) &_s_addr;
        socksize = sizeof(struct sockaddr_in6);
        s_addr->sin6_family = AF_INET6;
        memcpy(&s_addr->sin6_addr, addr, sizeof(struct in6_addr));
        s_addr->sin6_port = htons(port);
        v->conn = socket(AF_INET6, SOCK_DGRAM, 0);
    }

    if (bind(v->conn, (struct sockaddr *) &_s_addr, socksize) < 0) {
        close(v->conn);
        return -1;
    }
    return v->conn;
}

void posix_socket_close(struct emvpn_socket *v)
{
    close(v->conn);
    v->conn = -1;
}

int posix_random(uint8_t *data, int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int r;
    int e;
    if (fd < 0)
        return fd;
    r = read(fd, data, len);
    e = errno;
    close(fd);
    errno = e;
    return r;
}

static void posix_emvpn_timer_callback(void *arg)
{
    emvpn_core_timer_callback((struct emvpn_socket *)arg);
}


void posix_timer_add(struct emvpn_socket *v, uint64_t count)
{
    v->timer = evquick_addtimer(count, 0, posix_emvpn_timer_callback, v);
}

void posix_timer_defuse(struct emvpn_socket *v)
{
    evquick_deltimer(v->timer);
    v->timer = NULL;
}

uint64_t posix_time(void)
{
	struct timeval tv;
	unsigned long long ret;
	gettimeofday(&tv, NULL);
	ret = (unsigned long long)tv.tv_sec * 1000ULL;
	ret += (unsigned long long)tv.tv_usec / 1000ULL;
	return ret;
}


int posix_init(void)
{
    struct emvpn_sys posix = {
        .alloc = posix_alloc,
        .free = posix_free,
        .time = posix_time,
        .timer_add = posix_timer_add,
        .timer_defuse = posix_timer_defuse,
        .socket_connect = posix_socket_connect,
        .socket_listen = posix_socket_listen,
        .socket_send = posix_socket_send,
        .socket_recvfrom = posix_socket_recvfrom,
        .socket_close = posix_socket_close,
        .ntohs = posix_ntohs,
        .htons = posix_htons,
        .ntohl = posix_ntohl,
        .htohl = posix_htohl
    };
    return emvpn_sys_setup(&posix);
}


