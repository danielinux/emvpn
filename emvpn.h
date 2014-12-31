#include <stdint.h>
#include <string.h>
#ifndef VPN_H_INC
#define VPN_H_INC

#define VPN_DEFAULT_PORT 1294
#define VPN_MAX_PKT 1420
#define VPN_MAX_DATA (VPN_MAX_PKT - sizeof(struct emvpn_packet_msg) - sizeof(struct vp_data))

/****************************
 * Compiler selection
 */


#if defined __IAR_SYSTEMS_ICC__ || defined ATOP
#   define DEF_PACKED_STRUCT __packed struct
#   define DEF_PACKED_UNION  __packed union
#else
#   define DEF_PACKED_STRUCT struct __attribute__((packed))
#   define DEF_PACKED_UNION  union /* No need to pack unions in GCC */
#endif

enum emvpn_state {
    /* client */
    VPN_LOGIN_SENT = 0,
    VPN_RESPONSE_SENT,
    VPN_CLIENT_CONNECTED,
    VPN_IDLE,

    /* server */
    VPN_LISTEN,
    VPN_CHALLENGE_SENT,
    VPN_SERVER_CONNECTED,
    VPN_STALE,
    VPN_STATE_MAX
};

enum emvpn_msgtype {
    VM_LOGIN = 0,
    VM_CHALLENGE,
    VM_RESPONSE,
    VM_AUTH_OK,
    VM_AUTH_DENY,
    VM_IPCONFIG,
    VM_KEEPALIVE,
    VM_DATA,
    VM_RESET,
    VM_TYPE_MAX
};


#define VPN_KEY_LEN 32
#define VPN_MAX_USER 128
#define VPN_MAX_ADDR 128
#define VPN_IV_LEN  16
#define VPN_CHALLENGE_SIZE 512
#define VPN_SIGNATURE_SIZE 32 /* Sha2 */
#define VPN_MAX_RETRIES 3

#define VPN_TIMER_KEEPALIVE 10000
#define VPN_TIMER_HANDSHAKE 600

DEF_PACKED_STRUCT vpip_ipv4
{
    uint16_t family;
    uint16_t zero;
    uint32_t ip_addr;
    uint32_t ip_nm;
    uint32_t ip_gw;
    uint32_t ip_dns;
};

DEF_PACKED_STRUCT vpip_ipv6
{
    uint16_t family;
    uint16_t zero;
    uint8_t ip6_addr[16];
    uint8_t ip6_nm[16];
    uint8_t ip6_gw[16];
    uint8_t ip6_dns[16];
};

DEF_PACKED_UNION emvpn_ipconfig {
    struct vpip_ipv4 vp_ipv4;
    struct vpip_ipv6 vp_ipv6;
};


DEF_PACKED_STRUCT emvpn_packet {
    DEF_PACKED_STRUCT emvpn_packet_msg {
        uint16_t type;
        uint16_t tot_len;
    } vp_msg;
    DEF_PACKED_UNION emvpn_packet_payload {
        uint8_t vp_raw[0];
        char    vp_login[0];
        uint8_t vp_challenge[VPN_CHALLENGE_SIZE];
        DEF_PACKED_STRUCT vp_data {
            uint16_t  vpd_pkt_len;
            uint16_t  vpd_frag_len;
            uint8_t   vpd_frags;
            uint8_t   vpd_frag_id;
            uint32_t  vpd_counter;
            uint8_t   vpd_padding[6]; /* 16-bit alignment */
            uint8_t   vpd_signature[VPN_SIGNATURE_SIZE];
            uint8_t   vpd_data[0];
        } vp_data;
        DEF_PACKED_STRUCT vp_ipconfig {
            union emvpn_ipconfig ipconf;
            uint8_t            signature[VPN_SIGNATURE_SIZE];
        } vp_ipconf;
    } vp_payload;
};

#define VPN_DATA_OPTIONS_SIZE 16

struct emvpn_socket;


struct emvpn_session {
    struct emvpn_socket *sock;
    union emvpn_ipconfig ipconf;
    uint8_t *challenge;
    struct emvpn_session *next;
};

struct emvpn_key {
    uint8_t key[VPN_KEY_LEN];
    uint8_t  iv[VPN_IV_LEN];
};

struct emvpn_socket {
    int                 conn;
    void                *priv;
    char                user[VPN_MAX_USER];
    enum emvpn_state      state;
    void                *timer;
    int                 timer_retry;
    struct emvpn_key       key;
    uint8_t             ep_addr[VPN_MAX_ADDR];
    uint16_t            ep_port;
    uint16_t            ep_ipver;
    int                 (*emvpn_recv)(void *arg, uint8_t *data, int len);
    void                *emvpn_recv_arg;
    struct emvpn_session  *session;
    struct emvpn_socket   *next;
    uint8_t             *frag_pending;
    uint16_t            frag_tot_len;
    uint16_t            frag_offset;
};




#define VPN_CHECK_MSG(v, type) { \
    if (emvpn_ntohs((v)->vp_msg.type) != type) \
        return -1; \
}

#define VPN_CHECK_SIZE(v, tot_len, msg_len) { \
    if (emvpn_ntohs((v)->vp_msg.tot_len) != tot_len) \
        return -1; \
    if (msg_len && msg_len != (emvpn_ntohs(v)->vp_msg.tot_len - sizeof(struct emvpn_packet_msg))) \
        return -2; \
}


/* SYSTEM interface.  A system should implement these. */

struct emvpn_sys {


    /* Allocator */
    void* (*alloc)(int x);
    void  (*free)(void *x);

    /* Time function: return elapsed milliseconds */
    uint64_t (*time)(void);
    
    /* Time management */
    void (*timer_add)(struct emvpn_socket *v, uint64_t count);
    void (*timer_defuse)(struct emvpn_socket *v);
    
    int (*socket_connect)(struct emvpn_socket *v);
    int (*socket_listen)(struct emvpn_socket *v, uint16_t ip_ver, void *addr, uint16_t port);
    int (*socket_send)(struct emvpn_socket *v, void *pkt, int len);
    int (*socket_recvfrom)(struct emvpn_socket *v, void *pkt, int len, uint16_t *family, void *addr, uint16_t *port);
    void (*socket_close)(struct emvpn_socket *v);
    

    uint16_t (*ntohs)(uint16_t);
    uint16_t (*htons)(uint16_t);
    uint32_t (*ntohl)(uint32_t);
    uint32_t (*htohl)(uint32_t);
};

/* CRYPTO interface */
struct emvpn_crypto {
    int (*encrypt)(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len);
    int (*decrypt)(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len);
    void (*sign)(uint8_t *data, int len, uint8_t *signature);
};


/* SERVER APP interface */
struct emvpn_server {
    int is_server;
    /* Server DB calls: to be implemented if running a emvpn server */
    int (*get_key)(char *username, struct emvpn_key *key);
    int (*get_ipconf)(char *username, union emvpn_ipconfig *ipconf);
    int (*random)(uint8_t *buf, int len);
};

struct emvpn_dev {
    char *name;
    void *context;
    int (*xmit)(void *data, int len);
};

/* APP api */
    
/* Core calls: inform VPN about socket events */
void emvpn_core_socket_recv(struct emvpn_socket *v);
void emvpn_core_socket_error(struct emvpn_socket *v);
void emvpn_core_data_dispose(uint8_t *data);
void emvpn_core_send(struct emvpn_socket *v, uint8_t *data, int len);

/* Inform VPN about timer expiration */
void emvpn_core_timer_callback(struct emvpn_socket *v);

/* Recv from device */
void emvpn_core_dev_recv(void *data, int len);

int emvpn_sys_setup(struct emvpn_sys *sys);
int emvpn_crypto_setup(struct emvpn_crypto *crypto);
int emvpn_server_setup(struct emvpn_server *srv);
int emvpn_dev_setup(struct emvpn_dev *dev);


struct emvpn_socket *emvpn_client(uint16_t ip_version, void *addr, uint16_t port, char *user, struct emvpn_key *k);
struct emvpn_socket *emvpn_server(uint16_t ip_version, void *addr, uint16_t port);

#endif
