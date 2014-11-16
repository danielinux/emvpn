#include "emvpn.h"
#include <stdio.h>
#include <libevquick.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <libgen.h> /* basename() */

#ifdef VPN_SERVER

static struct emvpn_key secret = {
    "01234567890123456789012345678901",
    "6789012345678901"
};

int emvpn_get_key(char *user, struct emvpn_key *key)
{
    const uint8_t secret[VPN_KEY_LEN] = "01234567890123456789012345678901";
    memcpy(key, secret, sizeof(struct emvpn_key));
    return 0;
}

int emvpn_get_ipconf(char *user, union emvpn_ipconfig *ipconf)
{
    return -1;
}
#endif

int is_server = 0;
struct emvpn_socket *sock;

void usage(char *prg)
{
    fprintf(stderr, "Usage: %s [addr] [port]\n", prg);
    exit(6);
}

static void socket_cb(int fd, short rev, void *arg)
{
    struct emvpn_socket *v = (struct emvpn_socket *)arg;
    emvpn_core_socket_recv(v);
}

static void socket_err_cb(int fd, short rev, void *arg)
{
    struct emvpn_socket *v = (struct emvpn_socket *)arg;
    emvpn_core_socket_error(v);
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

    sock = emvpn_client(4, &addr, port, "test", &secret);
    if (!sock) {
        perror("Starting VPN client");
        exit(1);
    }
    evquick_addevent(sock->conn, EVQUICK_EV_READ, socket_cb, socket_err_cb, sock);
}

static void server(int argc, char *argv[])
{
    uint32_t addr = 0;
    uint16_t port = VPN_DEFAULT_PORT;

    printf("Starting server\n");

    if (argc > 1)
        port = atoi(argv[1]);

    sock = emvpn_server(4, &addr, port);
    if (!sock) {
        perror("Starting VPN server");
        exit(1);
    }
    evquick_addevent(sock->conn, EVQUICK_EV_READ, socket_cb, socket_err_cb, sock);

}

int main(int argc, char *argv[])
{
    if (strcmp(basename(argv[0]), "emvpn_server") == 0)
        is_server = 1;

    evquick_init();
    if (is_server)
        server(argc,argv);
    else
        client(argc,argv);
    
    for(;;) {
        evquick_loop();
    }
    return 0;
}
