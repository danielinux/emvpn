#include "emvpn.h"
#include <stdint.h>

#warning "compiling in UNSAFE mode (CRYPTO=none)"

int none_encrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    int i;
    for (i = 0; i < len; i++)
        to[i] = v->key.key[i % VPN_KEY_LEN] ^ from[i];
    return i;
}

int none_decrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    return none_encrypt(v, to, from, len);
}

void none_sign(uint8_t *data, int len, uint8_t *signature)
{
    (void)data;
    (void)len;
    memset(signature, 'x', VPN_SIGNATURE_SIZE);
}

int crypto_none_init(void)
{
    struct emvpn_crypto cpt = {
        .encrypt = none_encrypt,
        .decrypt = none_decrypt,
        .sign = none_sign

    };

    emvpn_crypto_setup(&cpt);

    return 0;

}
