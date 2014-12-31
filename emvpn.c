#include "emvpn.h"

/* Global data structures */
static struct emvpn_sys SYS;
static struct emvpn_dev DEV;
static struct emvpn_crypto CRYPTO;
static struct emvpn_server SRV;

/* Client socket */
static struct emvpn_socket *cli;


#define IS_SERVER() (SRV.is_server > 0)
#define emvpn_ntohs SYS.ntohs
#define emvpn_ntohl SYS.ntohl
#define emvpn_htons SYS.htons
#define emvpn_htonl SYS.htonl

#define emvpn_alloc SYS.alloc
#define emvpn_free SYS.free
#define emvpn_time SYS.time



/* Data methods / generic fn */
static void emvpn_data_single(struct emvpn_socket *v, void *data, int len) 
{
    DEV.xmit(data, len);
}

/* Receive data from the other endpoint of the tunnel.
 *
 * Gathering fragments is handled here. 
 */
static void emvpn_data(struct emvpn_socket *v, void *_data, int len) 
{
    struct emvpn_packet *pkt = (struct emvpn_packet *)_data;
    uint8_t sign[VPN_SIGNATURE_SIZE];
    uint8_t sign_calculated[VPN_SIGNATURE_SIZE];
    struct vp_data *data = emvpn_alloc(len - sizeof(struct emvpn_packet_msg));
    uint16_t pktlen, fraglen;
    uint8_t frags, frag_id;

    if (!data)
         return;

    /* Decrypt */
    if (CRYPTO.decrypt(v, (uint8_t *)data, pkt->vp_payload.vp_raw, len - sizeof(struct emvpn_packet_msg)) < 0)
        return;

    /* Verify signature just after decrypt */
    memcpy(sign, data->vpd_signature, VPN_SIGNATURE_SIZE);
    CRYPTO.sign(data->vpd_data, emvpn_ntohs(data->vpd_frag_len), sign_calculated);
    if (memcmp(sign_calculated, sign, VPN_SIGNATURE_SIZE) != 0) {
        /* Bad packet */
        return;
    }

    /* Adjust endianess */
    pktlen = emvpn_ntohs(data->vpd_pkt_len);
    fraglen = emvpn_ntohs(data->vpd_frag_len);
    frags = data->vpd_frags;
    frag_id = data->vpd_frag_id;

    /* Fragmentation */
    if (pktlen < fraglen)
        return; 
    if ((pktlen == fraglen) && 
        (frags == 1) && 
        (frag_id == 0)) {
            emvpn_data_single(v, data->vpd_data, pktlen);
            return;
    } else if ((frag_id == 0) && 
            (v->frag_offset == 0) &&
            (v->frag_pending == NULL) ) {

        v->frag_pending = emvpn_alloc(pktlen);
    }

    if (v->frag_pending && (v->frag_offset + fraglen <= pktlen)) {
        memcpy(v->frag_pending + v->frag_offset, data->vpd_data, fraglen);
        v->frag_offset += fraglen;
    }

    if (v->frag_offset == pktlen) {
        emvpn_data_single(v, v->frag_pending, v->frag_offset);
        emvpn_free(v->frag_pending);
        v->frag_pending = NULL;
        v->frag_offset = 0;
    }
}


    
static void emvpn_statetimer_add(struct emvpn_socket *v)
{
    uint64_t tlapse = (VPN_TIMER_HANDSHAKE << (uint64_t)v->timer_retry);
    if (v->state == VPN_CLIENT_CONNECTED || v->state == VPN_SERVER_CONNECTED)
        tlapse = VPN_TIMER_KEEPALIVE;
    SYS.timer_add(v, tlapse);
}

static int emvpn_dgram_send(struct emvpn_socket *v, enum emvpn_msgtype type, void *data, int len)
{
    struct emvpn_packet *pkt;
    uint16_t tot_len;

    if (len > 65535)
        return -1;
    
    tot_len = (uint16_t)len + (uint16_t)sizeof(struct emvpn_packet_msg);

    pkt = emvpn_alloc(tot_len);
    if (!pkt)
        return -1;

    pkt->vp_msg.type = emvpn_htons((uint16_t)(type & 0xFFFF));
    pkt->vp_msg.tot_len = emvpn_htons(tot_len);

    if (data)
        memcpy(pkt->vp_payload.vp_raw, data, len);

    return SYS.socket_send(v, pkt, tot_len);
}

/* Server */

struct emvpn_session *vlist = NULL;

static void vlist_add(struct emvpn_session *v)
{
    if (!vlist)
        vlist = v;
    else {
        v->next = vlist;
        vlist = v;
    }
}

static void vlist_del(struct emvpn_session *v)
{
    struct emvpn_session *cur = vlist, *prev = NULL;
    while(cur) {
        if (cur == v) {
            if (prev)
                prev->next = cur->next;
            else
                vlist = cur->next;
            emvpn_free(cur);
            break;
        }
        prev = cur;
        cur = cur->next; 
    }
}

static struct emvpn_session *vlist_find(uint16_t ipver, void *addr, uint16_t port)
{
    struct emvpn_session *cur = vlist;
    while(cur) {
        if (cur->sock) {
            if ((memcmp(cur->sock->ep_addr, addr, (cur->sock->ep_ipver == 4)?4:16) == 0) && cur->sock->ep_port == emvpn_ntohs(port))
                return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

static struct emvpn_session *new_session(char *user, uint16_t ipver, void *addr, uint16_t port)
{
    struct emvpn_session *vs;
    vs = emvpn_alloc(sizeof(struct emvpn_session));
    if (!vs)
        return NULL;

    /* Alloc new socket */
    vs->sock = emvpn_alloc(sizeof(struct emvpn_socket));
    if (!vs->sock) {
        emvpn_free(vs);
        return NULL;
    }

    strncpy(vs->sock->user, user, VPN_MAX_USER);
    SRV.get_key(vs->sock->user, &vs->sock->key);
    SRV.get_ipconf(vs->sock->user, &vs->ipconf);
    vs->sock->ep_ipver = ipver;
    vs->sock->ep_port = emvpn_ntohs(port);
    memcpy(vs->sock->ep_addr, addr, (ipver == 4)?4:16);
    if (SYS.socket_connect(vs->sock) < 0)  {
        emvpn_free(vs->sock);
        emvpn_free(vs);
        return NULL;
    }
    vs->sock->timer_retry = 0;
    vs->sock->session = vs;
    memcpy(vs->sock->user, user, VPN_MAX_USER);
    vlist_add(vs);
    return vs;
}

static void emvpn_send_challenge(struct emvpn_session *vs)
{
    uint8_t challenge[VPN_CHALLENGE_SIZE]; 
    vs->sock->state = VPN_STALE;

    if (SRV.random(challenge, VPN_CHALLENGE_SIZE) < 0)
        return;

    vs->challenge = emvpn_alloc(VPN_CHALLENGE_SIZE);
    if (!vs->challenge)
        return;

    if (CRYPTO.encrypt(vs->sock, vs->challenge, challenge, VPN_CHALLENGE_SIZE) == VPN_CHALLENGE_SIZE) {
        if (emvpn_dgram_send(vs->sock, VM_CHALLENGE, challenge, VPN_CHALLENGE_SIZE) > 0)
            vs->sock->state = VPN_CHALLENGE_SENT;
    }
}

static void emvpn_send_data(struct emvpn_socket *sck, void *data, int len)
{
    static uint8_t full_buffer[VPN_MAX_PKT] = {};
    static uint8_t full_buffer_enc[VPN_MAX_PKT] = {};
    struct emvpn_packet *pkt = (struct emvpn_packet *)full_buffer;
    struct emvpn_packet *pkt_enc = (struct emvpn_packet *)full_buffer_enc;
    uint16_t count, offset = 0, pktlen;
    uint16_t totlen = 0;
    int total = (len / VPN_MAX_PKT) + 1; 
    for (count = 0; count < total; count++) {
        pkt_enc->vp_msg.type = emvpn_htons(VM_DATA);
        pktlen = VPN_MAX_PKT;
        if ((len - offset) < pktlen) {
            pktlen = len - offset;
        }
        totlen = pktlen + VPN_DATA_OPTIONS_SIZE + VPN_SIGNATURE_SIZE;
        pkt_enc->vp_msg.tot_len = emvpn_htons(totlen + sizeof(struct emvpn_packet_msg));

        pkt->vp_payload.vp_data.vpd_frag_len = emvpn_htons(pktlen);
        pkt->vp_payload.vp_data.vpd_pkt_len = emvpn_htons((uint16_t)len);
        pkt->vp_payload.vp_data.vpd_frag_id = count & 0xff;
        pkt->vp_payload.vp_data.vpd_frags = total & 0xff;
        CRYPTO.sign((uint8_t *)data + offset, pktlen, pkt->vp_payload.vp_data.vpd_signature);
        memcpy(pkt->vp_payload.vp_data.vpd_data, (uint8_t *)data + offset, pktlen);
        if (CRYPTO.encrypt(sck, pkt_enc->vp_payload.vp_raw, pkt->vp_payload.vp_raw, totlen) > 0) {
            SYS.socket_send(sck, pkt_enc, totlen + sizeof(struct emvpn_packet_msg));
        }
        offset += pktlen;
    }
}

static void emvpn_login(struct emvpn_socket *sck, void *data, int len)
{
    struct emvpn_session *vs = sck->session;
    if (vs)
        emvpn_send_challenge(vs);
    emvpn_statetimer_add(vs->sock);
}

static void emvpn_response(struct emvpn_socket *sck, void *data, int len)
{
    struct emvpn_packet *pkt = (struct emvpn_packet *) data;
    struct emvpn_session *vs;
    
    vs = sck->session;
    if (!vs)
        return;
    if (memcmp(vs->challenge, pkt->vp_payload.vp_challenge, VPN_CHALLENGE_SIZE) == 0) {
        if (emvpn_dgram_send(sck, VM_AUTH_OK, NULL, 0) > 0)
            sck->state = VPN_SERVER_CONNECTED;
        else
            sck->state = VPN_STALE;
    }
    emvpn_free(vs->challenge);
    vs->challenge = NULL;
    emvpn_statetimer_add(vs->sock);
}

static void emvpn_rst(struct emvpn_socket *sck, void *data, int len)
{
    struct emvpn_session *vs;
    vs = sck->session;
    if (vs && vs->challenge) {
        emvpn_free(vs->challenge);
        vs->challenge = NULL;
    }
    sck->state = VPN_STALE;
    emvpn_statetimer_add(vs->sock);
}

static void emvpn_timeout_srv(struct emvpn_socket *v, uint64_t now)
{
    struct emvpn_session *vs;
    if (v->state == VPN_STALE) {
        vs = v->session;
        if (vs) {
            vlist_del(vs);
        }
        emvpn_free(v);
        return;
    }
    if (++v->timer_retry > VPN_MAX_RETRIES) {
        v->state = VPN_STALE;
    }
    if (v->state == VPN_SERVER_CONNECTED)
        emvpn_dgram_send(v, VM_KEEPALIVE, NULL, 0);
    emvpn_statetimer_add(v);
}



/* Client */

static void emvpn_ipconf(struct emvpn_socket *sck, void *data, int len)
{
    /* TODO: add SYSTEM function ... */

}

static void emvpn_challenge(struct emvpn_socket *v, void *data, int len)
{
    struct emvpn_packet *pkt = (struct emvpn_packet *)data;
    uint8_t response[VPN_CHALLENGE_SIZE];

    if (CRYPTO.encrypt(v, response, pkt->vp_payload.vp_challenge, VPN_CHALLENGE_SIZE) == VPN_CHALLENGE_SIZE) {
        if (emvpn_dgram_send(v, VM_RESPONSE, response, VPN_CHALLENGE_SIZE) > 0)
            v->state = VPN_RESPONSE_SENT;
        else
            v->state = VPN_IDLE;
    }
    emvpn_statetimer_add(v);
}

static void emvpn_ka(struct emvpn_socket *v, void *data, int len)
{
    /* Receive a keepalive. */
    v->timer_retry = 0;
    emvpn_statetimer_add(v);
}

static void emvpn_auth_ok(struct emvpn_socket *v, void *data, int len)
{
    v->timer_retry = 0;
    v->state = VPN_CLIENT_CONNECTED;
    cli = v;
    emvpn_statetimer_add(v); /* Schedule keepalives */
}


static int emvpn_send_login(struct emvpn_socket *v)
{
    v->state = VPN_IDLE;
    if (emvpn_dgram_send(v, VM_LOGIN, v->user, strlen(v->user)) > 0) {
        v->state = VPN_LOGIN_SENT;
        return 0;
    }
    return -1;
}

static void emvpn_auth_deny(struct emvpn_socket *v, void *data, int len)
{
    v->timer_retry = 0;
    emvpn_send_login(v);
    emvpn_statetimer_add(v); /* Schedule keepalives */
}

static void emvpn_timeout_cli(struct emvpn_socket *v, uint64_t now)
{
    if (++v->timer_retry > VPN_MAX_RETRIES) {
        v->timer_retry = 0;
        emvpn_send_login(v);
        emvpn_statetimer_add(v);
        /* Connection timed out, at any stage.
         * Restart from login.
         */
        return;
    }
    switch(v->state) {
        case VPN_IDLE:
        case VPN_LOGIN_SENT:
            emvpn_send_login(v); 
            /* fall through to activate timer */
        case VPN_RESPONSE_SENT:
            emvpn_statetimer_add(v);
            break;
        case VPN_CLIENT_CONNECTED:
            emvpn_dgram_send(v, VM_KEEPALIVE, NULL, 0);
            /* Fall through */
        default:
            emvpn_statetimer_add(v);
    }
}

void emvpn_core_data_dispose(uint8_t *data)
{
    uint8_t *origin;
    if (!data)
        return; 

    origin = (data - (sizeof(struct emvpn_packet_msg) + sizeof(struct vp_data)));
    emvpn_free(origin);
}

struct emvpn_socket *emvpn_client(uint16_t ip_version, void *addr, uint16_t port, char *user, struct emvpn_key *k)
{
    struct emvpn_socket *v = emvpn_alloc(sizeof(struct emvpn_socket));
    if (!v)
        return NULL;
    memcpy(&v->key, k, sizeof(struct emvpn_key));
    v->ep_ipver = ip_version;
    v->ep_port = port;
    memcpy(v->ep_addr, addr, (ip_version == 4)?4:16);
    if (SYS.socket_connect(v) < 0)  {
        emvpn_free(v);
        return NULL;
    }
    v->timer_retry = 0;
    memcpy(v->user, user, VPN_MAX_USER);
    if ((emvpn_send_login(v) < 0)) {
        emvpn_free(v);
        return NULL;
    }
    emvpn_statetimer_add(v);
    return v;
}

struct emvpn_socket *emvpn_server(uint16_t ip_version, void *addr, uint16_t port)
{
    struct emvpn_socket *v = emvpn_alloc(sizeof(struct emvpn_socket));
    if (!v)
        return NULL;
    if (SYS.socket_listen(v, ip_version, addr, port) < 0) {
        emvpn_free(v);
        return NULL;
    }
    v->state = VPN_LISTEN;
    return v;
}

struct emvpn_fsm_event {
    enum emvpn_state st;
    void (*ev_call[VM_TYPE_MAX])(struct emvpn_socket *sck, void *data, int len);
    void (*ev_timeout)(struct emvpn_socket *sck, uint64_t now);
};


struct emvpn_fsm_event emvpn_fsm[VPN_STATE_MAX] = {
/* { STATE                 { LOGIN   CHALLENGE       RESPONSE    AUTH_OK         DENY            IP_CONF     KA      DATA         RST     },   TIMEOUT         }*/
   { VPN_LOGIN_SENT,       { NULL,   emvpn_challenge,  NULL,       NULL,           NULL,           NULL,       NULL,   NULL,        NULL    }, emvpn_timeout_cli   },
   { VPN_RESPONSE_SENT,    { NULL,   NULL,           NULL,       emvpn_auth_ok,    emvpn_auth_deny,  NULL,       NULL,   NULL,        NULL    }, emvpn_timeout_cli   },
   { VPN_CLIENT_CONNECTED, { NULL,   NULL,           NULL,       NULL,           NULL,           emvpn_ipconf, emvpn_ka, emvpn_data,    NULL    }, emvpn_timeout_cli   },
   { VPN_IDLE,             { NULL,   NULL,           NULL,       NULL,           NULL,             NULL,       emvpn_ka, emvpn_data,    NULL    }, emvpn_timeout_cli   },
   { VPN_LISTEN,           { emvpn_login, NULL,        NULL,       NULL,           NULL,           NULL,       NULL,   NULL,        NULL    }, emvpn_timeout_srv   },
   { VPN_CHALLENGE_SENT,   { NULL,      NULL,        emvpn_response,   NULL,       NULL,           NULL,       NULL,   NULL,        emvpn_rst }, emvpn_timeout_srv   },
   { VPN_SERVER_CONNECTED, { NULL,      NULL,        NULL,           NULL,       NULL,           NULL,       emvpn_ka, emvpn_data,    NULL    }, emvpn_timeout_srv   },
   { VPN_STALE,            { NULL,      NULL,        NULL,           NULL,       NULL,           NULL,       emvpn_ka,   NULL,        emvpn_rst }, emvpn_timeout_srv   }
};


/* Public interface */
void emvpn_core_timer_callback(struct emvpn_socket *v)
{
    if (emvpn_fsm[v->state].ev_timeout)
        emvpn_fsm[v->state].ev_timeout(v, emvpn_time());
}

void emvpn_core_socket_err(struct emvpn_socket *v)
{
    SYS.socket_close(v);
    v->priv = NULL;
    v->conn = -1;
    if (IS_SERVER()) {
        v->state = VPN_STALE;
    } else {
        v->state = VPN_IDLE;
    }
}

static uint8_t pkt_buf[VPN_MAX_PKT];
void emvpn_core_socket_recv(struct emvpn_socket *v)
{
    int ret;
    uint16_t netver, port;
    uint8_t addr[16];
    struct emvpn_packet *pkt = (struct emvpn_packet *) pkt_buf;
    uint16_t pkt_type;

    if (v) {
        ret = SYS.socket_recvfrom(v, pkt_buf, VPN_MAX_PKT, &netver, addr, &port); 
        if (ret <= 0) {
            emvpn_core_socket_error(v);
            return;
        }
        pkt_type = emvpn_ntohs(pkt->vp_msg.type);
        if (pkt_type > VM_TYPE_MAX)
            return;

        if (v->state == VPN_LISTEN) {
            struct emvpn_session *vs;
            if (pkt_type == VM_LOGIN)  {
                vs = new_session(pkt->vp_payload.vp_login, netver, addr, port);
                vs->sock->conn = v->conn;
                vs->sock->priv = v->priv;
                v = vs->sock;
                v->state = VPN_LISTEN;
            } else {
                v = NULL;
                vs = vlist_find(netver, addr, port);
                if (vs)
                    v = vs->sock;
            }
            if (!v)
                return;
        }
        /* Sanity address check against stored endpoint */
        if (v->ep_ipver == netver && v->ep_port == emvpn_ntohs(port) && memcmp(v->ep_addr, addr, (netver == 4)?4:16) == 0) {
            /* Check if packet type is acceptable for the current state, and call the function */
            if (emvpn_fsm[v->state].ev_call[pkt_type]) {
                if (v->timer) {
                    SYS.timer_defuse(v);
                }
                emvpn_fsm[v->state].ev_call[pkt_type](v, pkt_buf, ret);
            }
        }
    }
}

void emvpn_core_socket_error(struct emvpn_socket *v)
{

}

void emvpn_core_send(struct emvpn_socket *v, uint8_t *data, int len)
{


}

void emvpn_core_dev_recv(void *data, int len)
{
    if (IS_SERVER()) {
        struct emvpn_session *cur = vlist;
        while(cur) {
            if (cur->sock->state == VPN_SERVER_CONNECTED) {
                emvpn_send_data(cur->sock, data, len);
            }
            cur = cur->next;
        }
    } else {
        if (cli->state == VPN_CLIENT_CONNECTED) {
            emvpn_send_data(cli, data, len);
        }
    }
}

/* Public interface to register functions */


int emvpn_sys_setup(struct emvpn_sys *sys)
{
    memcpy(&SYS, sys, sizeof(struct emvpn_sys));
    return 0;
}

int emvpn_crypto_setup(struct emvpn_crypto *crypto)
{
    memcpy(&CRYPTO, crypto, sizeof(struct emvpn_crypto));
    return 0;

}

int emvpn_server_setup(struct emvpn_server *srv)
{
    memcpy(&SRV, srv, sizeof(struct emvpn_server));
    SRV.is_server = 1;
    return 0;

}

int emvpn_dev_setup(struct emvpn_dev *dev)
{
    memcpy(&DEV, dev, sizeof(struct emvpn_dev));
    return 0;
}
