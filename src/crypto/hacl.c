#include "cose.h"
#include "edhoc/edhoc.h"
#include "crypto.h"
#include "format.h"

#if defined(HACL)

#include <EverCrypt_Curve25519.h>
#include <Lib_RandomBuffer_System.h>
#include <Hacl_Hash.h>
#include <Hacl_HKDF.h>
#include <Hacl_Ed25519.h>
#include "ccm.h"

int crypt_gen_keypair(cose_curve_t crv, cose_key_t *key) {
    int ret;

    // if true, key already initialized
    if (key->kty != COSE_KTY_NONE) {
        return EDHOC_SUCCESS;
    }

    if (crv == COSE_EC_CURVE_X25519) {
        Lib_RandomBuffer_System_randombytes(key->d, key->d_len);
        Hacl_Curve25519_51_secret_to_public(key->x, key->d);
        key->x_len = EDHOC_ECC_KEY_MAX_SIZE;
    } else {
        EDHOC_FAIL(EDHOC_ERR_KEYGEN);
    }

    exit:
    return ret;
}

int crypt_hash_init(hash_ctx_t *ctx) {
    (void) ctx;
    ctx->fill_level = 0;

    return EDHOC_SUCCESS;
}

int crypt_hash_update(hash_ctx_t *ctx, const uint8_t *in, size_t ilen) {
    if (ctx->fill_level + ilen > HASH_INPUT_BLEN)
        return EDHOC_ERR_CRYPTO;

    memcpy(ctx->input_buffer + ctx->fill_level, in, ilen);

    ctx->fill_level += ilen;

    return EDHOC_SUCCESS;
}

int crypt_hash_finish(hash_ctx_t *ctx, uint8_t *output) {
    Hacl_Hash_SHA2_hash_256(ctx->input_buffer, ctx->fill_level, output);
    return EDHOC_SUCCESS;
}

void crypt_hash_free(hash_ctx_t *ctx) {
    ctx->fill_level = 0;
}

int crypt_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, int length, uint8_t *out) {
    ssize_t ret;
    uint8_t info_buf[EDHOC_KDF_INFO_MAX_SIZE];
    ssize_t info_len;

    ret = EDHOC_ERR_CRYPTO;

    // TODO: check if the label length doesn't cause a buffer overflow. If label is too long, it will cause info_buf to
    //  overflow.

    if ((info_len = edhoc_info_encode(id, th, label, length, info_buf, EDHOC_SIG23_MAX_SIZE)) < EDHOC_SUCCESS) {
        ret = info_len;     // store the error code and return
        goto exit;
    }

    Hacl_HKDF_expand_sha2_256(out, (uint8_t *) prk, EDHOC_HASH_MAX_SIZE, info_buf, info_len, length);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

/**
 * @brief Compute the ECDH secret.
 *
 * @param[in] sk        COSE key where the private part must be set
 * @param[in] pk        COSE key where the public part must be set
 * @param[out] out      Output buffer, must be at least 32 bytes long
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns a negative value (i.e., EDHOC_ERR_CRYPTO, ...)
 */
static int crypt_ecdh(const cose_key_t *sk, const cose_key_t *pk, uint8_t *out) {

    EverCrypt_Curve25519_ecdh(out, (uint8_t *) sk->d, (uint8_t *) pk->x);

    return EDHOC_SUCCESS;
}

int crypt_derive_prk(const cose_key_t *sk,
                     const cose_key_t *pk,
                     const uint8_t *salt,
                     size_t salt_len,
                     uint8_t *prk) {
    int ret;

    uint8_t secret[EDHOC_SHARED_SECRET_MAX_SIZE];

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(crypt_ecdh(sk, pk, secret));

    Hacl_HMAC_compute_sha2_256(prk, (uint8_t *) salt, salt_len, (uint8_t *) secret, 32);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;

}


int crypt_decrypt(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *plaintext,
        uint8_t *ciphertext,
        size_t ct_pl_len,
        uint8_t *tag) {

    int ret;
    ret = EDHOC_SUCCESS;
    return ret;

}

int crypt_encrypt(cose_algo_t alg,
                  const uint8_t *key,
                  const uint8_t *iv,
                  const uint8_t *aad,
                  size_t aad_len,
                  uint8_t *plaintext,
                  uint8_t *ciphertext,
                  size_t ct_pl_len,
                  uint8_t *tag) {
    (void) alg;
    (void) ciphertext;

    int ret;

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(aes128_ccms_enc((uint8_t *) aad,
                                        aad_len,
                                        plaintext,
                                        (size_t *) &ct_pl_len,
                                        (uint8_t *) iv,
                                        2,
                                        (uint8_t *) key,
                                        8));
    memcpy(tag, &plaintext[ct_pl_len] - 8, 8);

    exit:
    return ret;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msg_len, uint8_t *signature) {

    Hacl_Ed25519_sign(signature, (uint8_t *) authkey->d, msg_len, (uint8_t *) msg);

    return 64;
}

#endif /* HACL */
