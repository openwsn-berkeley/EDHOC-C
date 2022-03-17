#include <string.h>

#include "edhoc/cose.h"
#include "edhoc/edhoc.h"
#include "crypto.h"

#if defined(TINYCRYPT)

#include "tinycrypt/constants.h"
#include "tinycrypt/hmac.h"
#include "tinycrypt/hkdf.h"
#include "tinycrypt/ccm_mode.h"
#include "c25519/c25519.h"
#include "c25519/edsign.h"

int crypt_gen_keypair(cose_curve_t crv, cose_key_t *key) {
    (void) crv;
    (void) key;
    return EDHOC_ERR_RANDOMNESS;
}

int crypt_copy_hash_context(sha_ctx_t *dstCtx, sha_ctx_t *srcCtx) {
    memcpy(dstCtx, srcCtx, sizeof(sha_ctx_t));

    return EDHOC_SUCCESS;
}

int crypt_hash_init(sha_ctx_t *ctx) {

    if (tc_sha256_init(ctx) == TC_CRYPTO_SUCCESS)
        return EDHOC_SUCCESS;
    else
        return EDHOC_ERR_CRYPTO;
}

int crypt_hash_update(sha_ctx_t *ctx, const uint8_t *in, size_t ilen) {

    if (tc_sha256_update(ctx, in, ilen) == TC_CRYPTO_SUCCESS)
        return EDHOC_SUCCESS;
    else
        return EDHOC_ERR_CRYPTO;
}

int crypt_hash_finish(sha_ctx_t *ctx, uint8_t *output) {
    if (tc_sha256_final(output, ctx) == TC_CRYPTO_SUCCESS)
        return EDHOC_SUCCESS;
    else
        return EDHOC_ERR_CRYPTO;
}

void crypt_hash_free(sha_ctx_t *ctx) {
    (void) ctx;
}

int crypt_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, uint8_t *out, size_t olen) {
    int ret;
    ret = EDHOC_ERR_CRYPTO;

    if (tc_hkdf_expand(prk, info, infoLen, olen, out) != TC_CRYPTO_SUCCESS) {
        goto exit;
    }

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

    uint8_t privateKey[C25519_EXPONENT_SIZE];

    memcpy(privateKey, sk->d, sk->dLen);
    c25519_prepare(privateKey);

    c25519_smult(out, pk->x, privateKey);

    return EDHOC_SUCCESS;
}

int crypt_derive_prk(const cose_key_t *sk,
                     const cose_key_t *pk,
                     const uint8_t *salt,
                     size_t saltLen,
                     uint8_t *prk) {
    int ret;
    struct tc_hmac_state_struct hmacCtx;
    memset(&hmacCtx, 0, sizeof(hmacCtx));

    uint8_t dhSecret[EDHOC_DH_SECRET_SIZE];

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(crypt_ecdh(sk, pk, dhSecret));

    if (tc_hmac_set_key(&hmacCtx, salt, saltLen) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_hmac_init(&hmacCtx) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_hmac_update(&hmacCtx, dhSecret, 32) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_hmac_final(prk, 32, &hmacCtx) != TC_CRYPTO_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;

}


int crypt_decrypt(const cose_key_t *sk,
                  const uint8_t *iv,
                  size_t ivLen,
                  const uint8_t *aad,
                  size_t aadLen,
                  uint8_t *in,
                  uint8_t *out,
                  size_t inOutLen,
                  uint8_t *tag,
                  size_t tagLen) {
    (void) tag;
    int ret;

    struct tc_ccm_mode_struct c;
    struct tc_aes_key_sched_struct sched;

    ret = EDHOC_ERR_CRYPTO;

    if (tc_aes128_set_encrypt_key(&sched, sk->k) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_ccm_config(&c, &sched, (uint8_t *) iv, ivLen, 8) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_ccm_decryption_verification(out, inOutLen, aad, aadLen, in, inOutLen + tagLen, &c) != TC_CRYPTO_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_encrypt(const cose_key_t *sk,
                  const uint8_t *iv,
                  size_t ivLen,
                  const uint8_t *aad,
                  size_t aadLen,
                  uint8_t *in,
                  uint8_t *out,
                  size_t inOutlen,
                  uint8_t *tag,
                  size_t tagLen) {

    int ret;
    struct tc_ccm_mode_struct c;
    struct tc_aes_key_sched_struct sched;

    ret = EDHOC_ERR_CRYPTO;

    if (tc_aes128_set_encrypt_key(&sched, sk->k) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_ccm_config(&c, &sched, (uint8_t *) iv, ivLen, 8) != TC_CRYPTO_SUCCESS)
        goto exit;

    if (tc_ccm_generation_encryption(out, (inOutlen + tagLen), aad, aadLen, in, inOutlen, &c) != TC_CRYPTO_SUCCESS)
        goto exit;

    memcpy(tag, out + inOutlen, tagLen);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen) {

    *sigLen = EDSIGN_SIGNATURE_SIZE;

    edsign_sign(signature, authkey->x, authkey->d, msg, msgLen);

    return EDHOC_SUCCESS;
}

int crypt_verify(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen) {
    *sigLen = EDSIGN_SIGNATURE_SIZE;

    if (edsign_verify(signature, authkey->x, msg, msgLen))
        return EDHOC_SUCCESS;
    else
        return EDHOC_ERR_CRYPTO;
}

#endif /* TINYCRYPT */
