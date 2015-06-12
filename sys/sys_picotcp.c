#include "emvpn.h"
#include "pico_socket.h"
#include "pico_stack.h"

struct picotcp_emvpn_socket {
    struct pico_socket *sock;
    struct pico_timer *tmr;
};

void *picotcp_alloc(int x){
    return PICO_ZALLOC(x);
}

void picotcp_free(void *x) {
    return PICO_FREE(x);
}

uint16_t picotcp_ntohs(uint16_t x)
{
    return short_be(x);
}

uint16_t picotcp_htons(uint16_t x)
{
    return short_be(x);
}

uint32_t picotcp_ntohl(uint32_t x)
{
    return long_be(x);
}

uint32_t picotcp_htohl(uint32_t x)
{
    return long_be(x);
}

int picotcp_socket_send(struct emvpn_socket *v, void *pkt, int len)
{
    struct picotcp_emvpn_socket *es = (struct picotcp_emvpn_socket *)v->priv;
    if (es)
        return pico_socket_sendto(es->sock, pkt, len, v->ep_addr, v->ep_port);
    return -1;
}

int picotcp_socket_recvfrom(struct emvpn_socket *v, void *pkt, int len, uint16_t *family, void *addr, uint16_t *port)
{
    struct picotcp_emvpn_socket *es = (struct picotcp_emvpn_socket *)v->priv;
    if (es) 
        return pico_socket_recvfrom(es->sock, pkt, len, addr, port);
    return -1;
}

static void picotcp_socket_callback(uint16_t ev, struct pico_socket *s)
{
    struct emvpn_socket *v = (struct emvpn_socket *) s->priv;
    emvpn_core_socket_recv(v);
}

int picotcp_socket_connect(struct emvpn_socket *v)
{
    struct picotcp_emvpn_socket *es = PICO_ZALLOC(sizeof(struct picotcp_emvpn_socket));
    if (!es)
        return -1;
    if (v->ep_ipver == 4) {
        es->sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, picotcp_socket_callback);
    } else if (v->ep_ipver == 6) {
        es->sock = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, picotcp_socket_callback);
    } else {
        PICO_FREE(es);
        return -1;
    }

    v->priv = es;
    es->sock->priv = v;
    v->conn = 0;
    return 0;
}

int picotcp_socket_listen(struct emvpn_socket *v, uint16_t ip_ver, void *addr, uint16_t port)
{
    struct picotcp_emvpn_socket *es = PICO_ZALLOC(sizeof(struct picotcp_emvpn_socket));
    if (!es)
        return -1;
    if (v->ep_ipver == 4) {
        es->sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, picotcp_socket_callback);
    } else if (v->ep_ipver == 6) {
        es->sock = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, picotcp_socket_callback);
    } else {
        PICO_FREE(es);
        return -1;
    }
    v->priv = es;
    es->sock->priv = v;
    v->conn = 0;
    pico_socket_bind(es->sock, addr, &port);
    return 0;
}

void picotcp_socket_close(struct emvpn_socket *v)
{
    struct picotcp_emvpn_socket *es = (struct picotcp_emvpn_socket *)v->priv;
    if (es) {
        pico_socket_close(es->sock);
        v->conn = -1;
        v->priv = NULL;
        PICO_FREE(es);
    }
}

int picotcp_random(uint8_t *data, int len)
{
    int r = 0;
    int i = 0;
    while(r < ((len/4)*4) ) {
        (*(uint32_t*)(data + r)) = pico_rand();
        r += 4;
    }
    for (i = 0; i < len % 4; i++) {
        *(data + r + i) = (uint8_t)(pico_rand() & 0xFF);
    }
    return r + i;
}

static void picotcp_emvpn_timer_callback(pico_time now, void *arg)
{
    emvpn_core_timer_callback((struct emvpn_socket *)arg);
}


void picotcp_timer_add(struct emvpn_socket *v, uint64_t count)
{
    struct picotcp_emvpn_socket *es = (struct picotcp_emvpn_socket *)v->priv;
    es->tmr = pico_timer_add(count, picotcp_emvpn_timer_callback, v);
}

void picotcp_timer_defuse(struct emvpn_socket *v)
{
    struct picotcp_emvpn_socket *es = (struct picotcp_emvpn_socket *)v->priv;
    pico_timer_cancel(es->tmr);
}

uint64_t picotcp_time(void)
{
    return PICO_TIME_MS();
}


int picotcp_init(void)
{
    struct emvpn_sys picotcp = {
        .alloc = picotcp_alloc,
        .free = picotcp_free,
        .time = picotcp_time,
        .timer_add = picotcp_timer_add,
        .timer_defuse = picotcp_timer_defuse,
        .socket_connect = picotcp_socket_connect,
        .socket_listen = picotcp_socket_listen,
        .socket_send = picotcp_socket_send,
        .socket_recvfrom = picotcp_socket_recvfrom,
        .socket_close = picotcp_socket_close,
        .ntohs = picotcp_ntohs,
        .htons = picotcp_htons,
        .ntohl = picotcp_ntohl,
        .htohl = picotcp_htohl
    };
    return emvpn_sys_setup(&picotcp);
}


