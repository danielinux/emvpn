#include "emvpn.h"
#include <stdio.h>
#include <libevquick.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <libgen.h> /* basename() */
#include <net/if.h> /* IFNAMSIZ */
#include <unistd.h>

#ifdef VPN_SERVER

static struct emvpn_key secret = {
    "01234567890123456789012345678901",
    "6789012345678901"
};

int demo_get_key(char *user, struct emvpn_key *key)
{
    const uint8_t secret[VPN_KEY_LEN] = "01234567890123456789012345678901";
    memcpy(key, secret, sizeof(struct emvpn_key));
    return 0;
}

int demo_get_ipconf(char *user, union emvpn_ipconfig *ipconf)
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

static void dev_cb(int fd, short rev, void *arg)
{
    unsigned char pkt[2048];
    int len;
    (void)arg;

    len = read(fd, pkt, 2048);
    if (len < 0)
        return;
    emvpn_core_dev_recv(pkt, len);
}

static void dev_err_cb(int fd, short rev, void *arg)
{

    fprintf(stderr, "TAP error \n");
    exit(5);    
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

int posix_random(uint8_t *data, int len);
static void server(int argc, char *argv[])
{
    uint32_t addr = 0;
    uint16_t port = VPN_DEFAULT_PORT;

    struct emvpn_server srv = {
        .get_key = demo_get_key,
        .get_ipconf = demo_get_ipconf,
        .random = posix_random
    };

    emvpn_server_setup(&srv);

    printf("Starting server\n");
    emvpn_server_setup(&srv);

    if (argc > 1)
        port = atoi(argv[1]);
    sock = emvpn_server(4, &addr, port);
    if (!sock) {
        perror("Starting VPN server");
        exit(1);
    }
    evquick_addevent(sock->conn, EVQUICK_EV_READ, socket_cb, socket_err_cb, sock);

}

extern int posix_init(void);
int drv_tap_init(char *name, void *opts);
int crypto_none_init(void);

int main(int argc, char *argv[])
{
    char devname[IFNAMSIZ] = "emvpn0";
    int tap_fd = -1;

    if(posix_init() < 0) {
        fprintf(stderr, "Error initializing posix module\n");
        return 1;
    }  
    
    if (strcmp(basename(argv[0]), "emvpn_server") == 0) {
        is_server = 1;
        strncpy(devname, "emsrv0", IFNAMSIZ);
    }

    tap_fd = drv_tap_init(devname, NULL);
    if (tap_fd < 0) {
        fprintf(stderr, "Error initializing TAP module. (Are you root?)\n");
        return 1;
    }  

    if (crypto_none_init() < 0) {
        fprintf(stderr, "Error initializing crypto module.\n");
        return 1;
    }  


    evquick_init();
    if (is_server)
        server(argc,argv);
    else
        client(argc,argv);

    evquick_addevent(tap_fd, EVQUICK_EV_READ, dev_cb, dev_err_cb, NULL);
    
    for(;;) {
        evquick_loop();
    }
    return 0;
}
