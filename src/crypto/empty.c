#include "edhoc/cose.h"
#include "edhoc/edhoc.h"

#if defined(EMPTY_CRYPTO)

int crypt_gen_keypair(cose_curve_t crv, cose_key_t *key) {
    (void) crv;
    (void) key;

    return EDHOC_SUCCESS;
}


int crypt_copy_hash_context(void *dstCtx, void *srcCtx) {
    (void) dstCtx;
    (void) srcCtx;

    return EDHOC_SUCCESS;
}

int crypt_hash_init(void *ctx) {
    (void) ctx;

    return EDHOC_SUCCESS;
}

int crypt_hash_update(void *ctx, const uint8_t *in, size_t ilen) {
    (void) ctx;
    (void) in;
    (void) ilen;

    return EDHOC_SUCCESS;
}

int crypt_hash_finish(void *ctx, uint8_t *out) {
    (void) ctx;
    (void) out;

    return EDHOC_SUCCESS;
}

void crypt_hash_free(void *ctx) {
    (void) ctx;
}

int crypt_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, uint8_t *out, size_t outLen) {
    (void) prk;
    (void) info;
    (void) infoLen;
    (void) out;
    (void) outLen;

    return EDHOC_SUCCESS;
}


int crypt_derive_prk(const cose_key_t *sk,
                     const cose_key_t *pk,
                     const uint8_t *salt,
                     size_t salt_len,
                     uint8_t *prk) {
    (void) sk;
    (void) pk;
    (void) salt;
    (void) salt_len;
    (void) prk;

    return EDHOC_SUCCESS;
}

int crypt_encrypt(
        const cose_key_t *sk,
        const uint8_t *iv,
        size_t ivLen,
        const uint8_t *aad,
        size_t aadLen,
        uint8_t *in,
        uint8_t *out,
        size_t inOutLen,
        uint8_t *tag,
        size_t tagLen) {
    (void) sk;
    (void) iv;
    (void) ivLen;
    (void) aad;
    (void) aadLen;
    (void) in;
    (void) out;
    (void) inOutLen;
    (void) tag;
    (void) tag;
    (void) tagLen;

    return EDHOC_SUCCESS;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen) {
    (void) authkey;
    (void) msg;
    (void) msgLen;
    (void) signature;
    (void) sigLen;

    return EDHOC_SUCCESS;
}

#endif /* EMPTY_CRYPTO */
