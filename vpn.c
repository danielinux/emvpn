#include "arch.h"
#include "vpn.h"

/* Server */
struct vpn_socket *vlist = NULL;

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


struct vpn_fsm_event {
    enum vpn_state st;
    void (*ev_call[VM_TYPE_MAX])(struct vpn_socket *sck, void *data, int len);
    void (*ev_timeout)(struct vpn_socket *sck, uint64_t now);
};

/* Public interface */

static int vpn_send(struct vpn_socket *v, enum vpn_msgtype type, void *data, int len)
{


}

/* Client */

static int vpn_send_login(struct vpn_socket *v)
{
    v->state = VPN_IDLE;
    if (vpn_send(v, VM_LOGIN, v->user, strlen(v->user)) > 0) {
        v->state = VPN_LOGIN_SENT;
        /* TODO: set timeout */
        return 0;
    }
    /* TODO: set timeout */
    return -1;
}

struct vpn_socket *vpn_client(uint16_t ip_version, void *addr, uint16_t port, char *user, struct vpn_key *k)
{
    struct vpn_socket *v = vpn_alloc(sizeof(struct vpn_socket));
    if (!v)
        return NULL;
    memcpy(&v->key, k, sizeof(struct vpn_key));
    v->conn = vpn_socket_open(ip_version, addr, port);
    memcpy(v->user, user, VPN_MAX_USER);
    if (vpn_socket_err(v->conn) || vpn_send_login(v) < 0) {
        vpn_free(v);
        return NULL;
    }
    return v;
}

struct vpn_fsm_event vpn_fsm[VPN_STATE_MAX] = {
/* { STATE                 { LOGIN   CHALLENGE       RESPONSE    AUTH_OK         DENY            IP_CONF     KA      DATA        FRAG      RST     },   TIMEOUT         }*/
   { VPN_LOGIN_SENT,       { NULL,   vpn_challenge,  NULL,       NULL,           NULL,           NULL,       NULL,   NULL,       NULL,     NULL    }, vpn_timeout_cli   },
   { VPN_RESPONSE_SENT,    { NULL,   NULL,           NULL,       vpn_auth_ok,    vpn_auth_deny,  NULL,       NULL,   NULL,       NULL,     NULL    }, vpn_timeout_cli   },
   { VPN_CLIENT_CONNECTED, { NULL,   vpn_restart,    NULL,       NULL,           NULL,           vpn_ipconf, vpn_ka, vpn_data,   vpn_frag, NULL    }, vpn_timeout_ka    },
   { VPN_IDLE,             {                                                                                                                       }, vpn_timeout_cli   },
   { VPN_LISTEN,           { vpn_login                                                                                                             }, vpn_timeout_srv   },
   { VPN_CHALLENGE_SENT,   { NULL,      NULL,        vpn_response,   NULL,       NULL,           NULL,       NULL,   NULL,       NULL,     vpn_rst }, vpn_timeout_srv   },
   { VPN_SERVER_CONNECTED, { vpn_login, NULL,        NULL,           NULL,       NULL,           NULL,       vpn_ka, vpn_data,   vpn_frag, vpn_rst }, vpn_timeout_ka    }
};


