#include "vpn.h"
#include <stdio.h>
#include <libevquick.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#ifdef VPN_SERVER

static struct vpn_key secret = {
    "01234567890123456789012345678901",
    "6789012345678901"
};

int vpn_get_key(char *user, struct vpn_key *key)
{
    const uint8_t secret[VPN_KEY_LEN] = "01234567890123456789012345678901";
    memcpy(key, secret, sizeof(struct vpn_key));
    return 0;
}

int vpn_get_ipconf(char *user, union vpn_ipconfig *ipconf)
{
    return -1;
}
#endif

int is_server = 0;
struct vpn_socket *sock;

void usage(char *prg)
{
    fprintf(stderr, "Usage: %s [addr] [port]\n", prg);
    exit(6);

}

static void client_cb(int fd, short rev, void *arg)
{
    struct vpn_socket *v = (struct vpn_socket *)arg;
    vpn_core_socket_recv(v);
}

static void client_err_cb(int fd, short rev, void *arg)
{
    struct vpn_socket *v = (struct vpn_socket *)arg;
    vpn_core_socket_error(v);
}

static void client(int argc, char *argv[])
{
    uint32_t addr = 0;
    uint16_t port = VPN_DEFAULT_PORT;

    if (argc < 2)
        usage(argv[0]);

    printf("Starting client\n");


    if (argc > 2)
        port = htons(atoi(argv[2]));

    if (inet_aton(argv[1], (struct in_addr *)&addr) < 0)
        exit(2);

    sock = vpn_client(4, &addr, port, "test", &secret);
    evquick_addevent(sock->conn, EVQUICK_EV_READ, client_cb, client_err_cb, sock);
}

static void server(int argc, char *argv[])
{
    exit(1);

}

int main(int argc, char *argv[])
{
    if (strcmp(argv[0], "vpn_server") == 0)
        is_server = 1;

    evquick_init();

    if (is_server) /* TODO */
        server(argc,argv);
    else
        client(argc,argv);
    
    for(;;) {
        evquick_loop();
    }

    return 0;
}
