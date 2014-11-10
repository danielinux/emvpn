#include "vpn.h"
#include <stdint.h>

#warning "compiling in UNSAFE mode (CRYPTO=none)"

int vpn_encrypt(struct vpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    int i;
    for (i = 0; i < len; i++)
        to[i] = v->key.key[i % VPN_KEY_LEN] ^ from[i];
    return i;
}

int vpn_decrypt(struct vpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    return vpn_encrypt(v, to, from, len);
}

