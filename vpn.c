#include "vpn.h"

/* Server */
struct vpn_socket *vlist = NULL;

/* Data methods / generic fn */
static void vpn_data(struct vpn_socket *sck, void *data, int len) 
{

}

/* Client methods */
static void vpn_ipconf(struct vpn_socket *sck, void *data, int len)
{

}

/* Server methods */
static void vpn_login(struct vpn_socket *sck, void *data, int len)
{

}

static void vpn_response(struct vpn_socket *sck, void *data, int len)
{

}

static void vpn_rst(struct vpn_socket *sck, void *data, int len)
{

}

static void vpn_timeout_srv(struct vpn_socket *sck, uint64_t now)
{

}

static void vlist_add(struct vpn_socket *v)
{
    v->next = vlist;
}

static void vlist_del(struct vpn_socket *v)
{
    struct vpn_socket *cur = vlist, *prev = NULL;
    while(cur) {
        if (cur == v) {
            if (prev)
                prev->next = cur->next;
            else
                vlist = cur->next;
            vpn_free(cur);
            break;
        }
        prev = cur;
        cur = cur->next; 
    }
}



static int vpn_dgram_send(struct vpn_socket *v, enum vpn_msgtype type, void *data, int len)
{
    struct vpn_packet *pkt;
    uint16_t tot_len;

    if (len > 65535)
        return -1;
    
    tot_len = (uint16_t)len + (uint16_t)sizeof(struct vpn_packet_msg);

    pkt = vpn_alloc(tot_len);
    if (!pkt)
        return -1;

    pkt->vp_msg.type = vpn_htons((uint16_t)(type & 0xFFFF));
    pkt->vp_msg.tot_len = vpn_htons(tot_len);

    if (data)
        memcpy(pkt->vp_payload.vp_raw, data, len);

    return vpn_socket_send(v, pkt, tot_len);
}


static void vpn_statetimer_add(struct vpn_socket *v)
{
    uint64_t tlapse = (VPN_TIMER_HANDSHAKE << (uint64_t)v->timer_retry);
    if (v->state == VPN_CLIENT_CONNECTED || v->state == VPN_SERVER_CONNECTED)
        tlapse = VPN_TIMER_KEEPALIVE;
    vpn_timer_add(v, tlapse);
}

/* Client */


static void vpn_challenge(struct vpn_socket *v, void *data, int len)
{
    struct vpn_packet *pkt = (struct vpn_packet *)data;
    uint8_t response[VPN_CHALLENGE_SIZE];

    if (vpn_encrypt(v, response, pkt->vp_payload.vp_challenge, VPN_CHALLENGE_SIZE) == VPN_CHALLENGE_SIZE) {
        if (vpn_dgram_send(v, VM_RESPONSE, response, VPN_CHALLENGE_SIZE) > 0)
            v->state = VPN_RESPONSE_SENT;
        else
            v->state = VPN_IDLE;
    }
    vpn_statetimer_add(v);
}

static void vpn_ka(struct vpn_socket *v, void *data, int len)
{
    /* Receive a keepalive. */
    v->timer_retry = 0;
}

static void vpn_auth_ok(struct vpn_socket *v, void *data, int len)
{
    v->timer_retry = 0;
    v->state = VPN_CLIENT_CONNECTED;
    vpn_statetimer_add(v); /* Schedule keepalives */
}


static int vpn_send_login(struct vpn_socket *v)
{
    v->state = VPN_IDLE;
    if (vpn_dgram_send(v, VM_LOGIN, v->user, strlen(v->user)) > 0) {
        v->state = VPN_LOGIN_SENT;
        return 0;
    }
    return -1;
}

static void vpn_auth_deny(struct vpn_socket *v, void *data, int len)
{
    v->timer_retry = 0;
    vpn_send_login(v);
    vpn_statetimer_add(v); /* Schedule keepalives */
}

static void vpn_timeout_cli(struct vpn_socket *v, uint64_t now)
{
    if (++v->timer_retry > VPN_MAX_RETRIES) {
        v->timer_retry = 0;
        vpn_send_login(v);
        vpn_statetimer_add(v);
        /* Connection timed out, at any stage.
         * Restart from login.
         */
        return;
    }
    switch(v->state) {
        case VPN_IDLE:
        case VPN_LOGIN_SENT:
            vpn_send_login(v); 
            /* fall through to activate timer */
        case VPN_RESPONSE_SENT:
            vpn_statetimer_add(v);
            break;
        case VPN_CLIENT_CONNECTED:
            vpn_dgram_send(v, VM_KEEPALIVE, NULL, 0);
            /* Fall through */
        default:
            vpn_statetimer_add(v);
    }
}

void vpn_dispose_data(uint8_t *data)
{
    uint8_t *origin;
    if (!data)
        return; 

    origin = (data - (sizeof(struct vpn_packet_msg) + sizeof(struct vp_data)));
    vpn_free(origin);
}

struct vpn_socket *vpn_client(uint16_t ip_version, void *addr, uint16_t port, char *user, struct vpn_key *k)
{
    struct vpn_socket *v = vpn_alloc(sizeof(struct vpn_socket));
    if (!v)
        return NULL;
    memcpy(&v->key, k, sizeof(struct vpn_key));
    v->ep_ipver = ip_version;
    v->ep_port = port;
    memcpy(v->ep_addr, addr, (ip_version == 4)?4:16);
    if (vpn_socket_connect(v) < 0)  {
        vpn_free(v);
        return NULL;
    }
    v->timer_retry = 0;
    memcpy(v->user, user, VPN_MAX_USER);
    if ((vpn_send_login(v) < 0)) {
        vpn_free(v);
        return NULL;
    }
    vpn_statetimer_add(v);
    return v;
}

struct vpn_fsm_event {
    enum vpn_state st;
    void (*ev_call[VM_TYPE_MAX])(struct vpn_socket *sck, void *data, int len);
    void (*ev_timeout)(struct vpn_socket *sck, uint64_t now);
};


struct vpn_fsm_event vpn_fsm[VPN_STATE_MAX] = {
/* { STATE                 { LOGIN   CHALLENGE       RESPONSE    AUTH_OK         DENY            IP_CONF     KA      DATA         RST     },   TIMEOUT         }*/
   { VPN_LOGIN_SENT,       { NULL,   vpn_challenge,  NULL,       NULL,           NULL,           NULL,       NULL,   NULL,        NULL    }, vpn_timeout_cli   },
   { VPN_RESPONSE_SENT,    { NULL,   NULL,           NULL,       vpn_auth_ok,    vpn_auth_deny,  NULL,       NULL,   NULL,        NULL    }, vpn_timeout_cli   },
   { VPN_CLIENT_CONNECTED, { NULL,   NULL,    NULL,       NULL,           NULL,           vpn_ipconf, vpn_ka, vpn_data,    NULL    }, vpn_timeout_cli   },
   { VPN_IDLE,             {                                                                                                              }, vpn_timeout_cli   },
   { VPN_LISTEN,           { vpn_login                                                                                                    }, vpn_timeout_srv   },
   { VPN_CHALLENGE_SENT,   { NULL,      NULL,        vpn_response,   NULL,       NULL,           NULL,       NULL,   NULL,        vpn_rst }, vpn_timeout_srv   },
   { VPN_SERVER_CONNECTED, { vpn_login, NULL,        NULL,           NULL,       NULL,           NULL,       vpn_ka, vpn_data,    vpn_rst }, vpn_timeout_srv   }
};


/* Public interface */
void vpn_timer_callback(struct vpn_socket *v)
{
    if (vpn_fsm[v->state].ev_timeout)
        vpn_fsm[v->state].ev_timeout(v, vpn_time());
}
