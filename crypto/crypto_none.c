#include "emvpn.h"
#include <stdint.h>

#warning "compiling in UNSAFE mode (CRYPTO=none)"

int emvpn_encrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    int i;
    for (i = 0; i < len; i++)
        to[i] = v->key.key[i % VPN_KEY_LEN] ^ from[i];
    return i;
}

int emvpn_decrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    return emvpn_encrypt(v, to, from, len);
}

