#include "emvpn.h"
#include <stdint.h>
#include "openssl/evp.h"
#include "openssl/sha.h"

static EVP_CIPHER_CTX enc, dec;
static SHA256_CTX sha;


int openssl_encrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    int clen, flen = 0;
    EVP_CIPHER_CTX_init(&enc);
    EVP_EncryptInit(&enc, EVP_aes_256_cbc(), v->key.key, v->key.iv);
    EVP_EncryptUpdate(&enc, to, &clen, from, len);
    EVP_EncryptFinal_ex(&enc, to + clen, &flen);
    return clen + (flen % 16) ;
}

int openssl_decrypt(struct emvpn_socket *v, uint8_t *to, uint8_t *from, int len)
{
    int clen, flen = 0;
    EVP_CIPHER_CTX_init(&dec);
    EVP_DecryptInit(&dec, EVP_aes_256_cbc(), v->key.key, v->key.iv);
    EVP_DecryptUpdate(&dec, to, &clen, from, len);
    EVP_DecryptFinal_ex(&dec, to + clen, &flen);
    return clen + (flen % 16) ;
}

void openssl_sign(uint8_t *data, int len, uint8_t *signature)
{
    SHA256_Update(&sha, data, len);
    SHA256_Final(signature, &sha);
}

int crypto_openssl_init(void)
{
    struct emvpn_crypto cpt = {
        .encrypt = openssl_encrypt,
        .decrypt = openssl_decrypt,
        .sign = openssl_sign

    };

    SHA256_Init(&sha);
    emvpn_crypto_setup(&cpt);
    return 0;
}
