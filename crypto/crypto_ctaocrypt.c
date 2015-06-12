#include "emvpn.h"
#include <stdint.h>
#include "cyassl/ctaocrypt/sha256.h"
#include "cyassl/ctaocrypt/aes.h"
static Sha256 sha;
static Aes enc;
static Aes dec;

int ctaocrypt_encrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    AesSetKey(&enc, v->key.key, VPN_KEY_LEN, v->key.iv, AES_ENCRYPTION);
    if (AesCbcEncrypt(&enc, to, from, len) == 0)
        return len;
    return 0;
}

int ctaocrypt_decrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    AesSetKey(&dec, v->key.key, VPN_KEY_LEN, v->key.iv, AES_DECRYPTION);
    if (AesCbcDecrypt(&dec, to, from, len) == 0)
        return len;
    return 0;
}

void ctaocrypt_sign(uint8_t *data, int len, uint8_t *signature)
{
    Sha256Update(&sha, data, len);
    Sha256Final(&sha, signature);
}

int crypto_ctaocrypt_init(void)
{
    struct emvpn_crypto cpt = {
        .encrypt = ctaocrypt_encrypt,
        .decrypt = ctaocrypt_decrypt,
        .sign = ctaocrypt_sign

    };

    InitSha256(&sha);
    emvpn_crypto_setup(&cpt);

    return 0;
}
