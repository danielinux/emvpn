#include <stdint.h>
#include <string.h>
#ifndef VPN_H_INC
#define VPN_H_INC

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

enum vpn_state {
    VPN_LOGIN_SENT = 0,
    VPN_RESPONSE_SENT,
    VPN_CLIENT_CONNECTED,

    VPN_IDLE,

    VPN_LISTEN,
    VPN_CHALLENGE_SENT,
    VPN_SERVER_CONNECTED,
    VPN_STATE_MAX
};

enum vpn_msgtype {
    VM_LOGIN = 0,
    VM_CHALLENGE,
    VM_RESPONSE,
    VM_AUTH_OK,
    VM_AUTH_DENY,
    VM_KEEPALIVE,
    VM_IPCONFIG,
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
    uint32_t ip_addr;
    uint32_t ip_nm;
    uint32_t ip_gw;
    uint32_t ip_dns;
};

DEF_PACKED_STRUCT vpip_ipv6
{
    uint8_t ip6_addr[16];
    uint8_t ip6_nm[16];
    uint8_t ip6_gw[16];
    uint8_t ip6_dns[16];
};



DEF_PACKED_STRUCT vpn_packet {
    DEF_PACKED_STRUCT vpn_packet_msg {
        uint16_t type;
        uint16_t tot_len;
    } vp_msg;
    DEF_PACKED_UNION vpn_packet_payload {
        uint8_t vp_raw[0];
        uint8_t vp_login[0];
        uint8_t vp_challenge[VPN_CHALLENGE_SIZE];
        DEF_PACKED_STRUCT vp_data {
            uint8_t vpd_frags;
            uint8_t vpd_frag_id;
            uint8_t vpd_padding;
            uint8_t vpd_reserved;
            uint32_t vpd_counter;
            uint8_t  vpd_signature[VPN_SIGNATURE_SIZE];
            uint8_t  vpd_data[0];
        } vp_data;
        DEF_PACKED_STRUCT vp_ipconfig {
            DEF_PACKED_UNION vpip_ver {
                struct vpip_ipv4 vpip_ipv4;
                struct vpip_ipv6 vpip_ipv6;
                uint8_t  vpd_signature[VPN_SIGNATURE_SIZE];
            } vpip_ipv4;
        } vp_ipconf;
    } vp_payload;
};


struct vpn_key {
    uint8_t key[VPN_KEY_LEN];
    uint8_t  iv[VPN_IV_LEN];
};

struct vpn_socket {
    int                 conn;
    void                *priv;
    char                user[VPN_MAX_USER];
    enum vpn_state      state;
    void                *timer;
    int                 timer_retry;
    struct vpn_key       key;
    uint8_t             ep_addr[VPN_MAX_ADDR];
    uint16_t            ep_port;
    uint16_t            ep_ipver;
    int                 (*vpn_recv)(void *arg, uint8_t *data, int len);
    void                *vpn_recv_arg;
    struct vpn_socket   *next;
};



/* Macros */
#define IS_SERVER(v) (((v)->state > VPN_IDLE))

#define VPN_CHECK_MSG(v, type) { \
    if (vpn_ntohs((v)->vp_msg.type) != type) \
        return -1; \
}

#define VPN_CHECK_SIZE(v, tot_len, msg_len) { \
    if (vpn_ntohs((v)->vp_msg.tot_len) != tot_len) \
        return -1; \
    if (msg_len && msg_len != (vpn_ntohs(v)->vp_msg.tot_len - sizeof(struct vpn_packet_msg))) \
        return -2; \
}


/* SYSTEM interface. */
void *vpn_alloc(int x);
void vpn_free(void *x);
int vpn_socket_send(struct vpn_socket *v, void *pkt, int len);
int vpn_socket_connect(struct vpn_socket *v);
void vpn_timer_add(struct vpn_socket *v, uint64_t count);
uint64_t vpn_time(void);

uint16_t vpn_ntohs(uint16_t);
uint16_t vpn_htons(uint16_t);
uint32_t vpn_ntohl(uint32_t);
uint32_t vpn_htohl(uint32_t);

/* CRYPTO interface */
int vpn_encrypt(struct vpn_socket *v, uint8_t *to, uint8_t *from, int len);
int vpn_decrypt(struct vpn_socket *v, uint8_t *to, uint8_t *from, int len);


/* Call me back in case of timer expiration */
void vpn_timer_callback(struct vpn_socket *v);


#endif
