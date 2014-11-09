#ifndef VPN_H_INC
#define VPN_H_INC
#include "arch.h"
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
    VM_DATA_FRAG,
    VM_RESET,
    VM_TYPE_MAX
};


#define VPN_KEY_LEN 32
#define VPN_MAX_USER 128
#define VPN_IV_LEN  16
#define VPN_CHALLENGE_SIZE 512
#define VPN_SIGNATURE_SIZE 32 /* Sha2 */


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
    struct vpn_packet_msg {
        uint16_t type;
        uint16_t tot_len;
    } vp_msg;
    DEF_PACKED_UNION vpn_packet_payload {
        char vp_login[0];
        char vp_challenge[VPN_CHALLENGE_SIZE];
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
            };
        } vp_ipconf;
    } vp_payload;
};


struct vpn_key {
    uint8_t key[VPN_KEY_LEN];
    uint8_t  iv[VPN_IV_LEN];
};

struct vpn_socket {
    VPNSOCKET           conn;
    char                user[VPN_MAX_USER];
    enum vpn_state      state;
    struct vpn_key       key;
    struct vpn_socket   *next;:
};




#define IS_SERVER(v) (((v)->state > VPN_IDLE))

/* Data methods / generic fn */
static void vpn_data(struct vpn_socket *sck, void *data, int len);
static void vpn_frag(struct vpn_socket *sck, void *data, int len);
static void vpn_timeout_ka(struct vpn_socket *sck, uint64_t now);


/* Client methods */
static void vpn_challenge(struct vpn_socket *sck, void *data, int len);
static void vpn_auth_ok(struct vpn_socket *sck, void *data, int len);
static void vpn_auth_deny(struct vpn_socket *sck, void *data, int len);
static void vpn_restart(struct vpn_socket *sck, void *data, int len);
static void vpn_ka(struct vpn_socket *sck, void *data, int len);
static void vpn_ipconf(struct vpn_socket *sck, void *data, int len);
static void vpn_timeout_cli(struct vpn_socket *sck, uint64_t now);

/* Server methods */
static void vpn_login(struct vpn_socket *sck, void *data, int len);
static void vpn_response(struct vpn_socket *sck, void *data, int len);
static void vpn_rst(struct vpn_socket *sck, void *data, int len);
static void vpn_timeout_srv(struct vpn_socket *sck, uint64_t now);


#endif
