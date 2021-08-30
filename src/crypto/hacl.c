#include "edhoc/cose.h"
#include "edhoc/edhoc.h"
#include "crypto.h"

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
        Lib_RandomBuffer_System_randombytes(key->d, key->dLen);
        Hacl_Curve25519_51_secret_to_public(key->x, key->d);
        key->xLen = COSE_ECC_KEY_SIZE;
    } else {
        EDHOC_FAIL(EDHOC_ERR_KEYGEN);
    }

    exit:
    return ret;
}

int crypt_copy_hash_context(sha_ctx_t *dstCtx, sha_ctx_t *srcCtx) {
    memcpy(dstCtx, srcCtx, sizeof(sha_ctx_t));
    return EDHOC_SUCCESS;
}

int crypt_hash_init(sha_ctx_t *ctx) {
    ctx->fillLevel = 0;

    return EDHOC_SUCCESS;
}

int crypt_hash_update(sha_ctx_t *ctx, const uint8_t *in, size_t ilen) {
    if (ctx->fillLevel + ilen > HASH_INPUT_BLEN)
        return EDHOC_ERR_CRYPTO;

    memcpy(ctx->buffer + ctx->fillLevel, in, ilen);

    ctx->fillLevel += ilen;

    return EDHOC_SUCCESS;
}

int crypt_hash_finish(sha_ctx_t *ctx, uint8_t *output) {
    Hacl_Hash_SHA2_hash_256(ctx->buffer, ctx->fillLevel, output);
    return EDHOC_SUCCESS;
}

void crypt_hash_free(sha_ctx_t *ctx) {
    ctx->fillLevel = 0;
    memset(ctx->buffer, 0, HASH_INPUT_BLEN);
}

int crypt_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, uint8_t *out, size_t outlen) {
    Hacl_HKDF_expand_sha2_256(out, (uint8_t *) prk, EDHOC_DIGEST_SIZE, (uint8_t *) info, infoLen, outlen);

    return EDHOC_SUCCESS;
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

    uint8_t secret[EDHOC_DH_SECRET_SIZE];

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(crypt_ecdh(sk, pk, secret));

    Hacl_HMAC_compute_sha2_256(prk, (uint8_t *) salt, salt_len, (uint8_t *) secret, 32);

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
    (void) ivLen;
    int ret;
    uint8_t temp[EDHOC_PLAINTEXT23_SIZE];
    size_t tempSize;

    if (in != out)
        return EDHOC_ERR_CRYPTO;

    memcpy(temp, in, inOutLen);
    memcpy(temp + inOutLen, tag, tagLen);

    tempSize = inOutLen + tagLen;

    EDHOC_CHECK_SUCCESS(aes128_ccms_dec((uint8_t *) aad,
                                        aadLen,
                                        temp,
                                        (size_t *) &(tempSize),
                                        (uint8_t *) iv,
                                        2,
                                        (uint8_t *) sk->k,
                                        8));
    memcpy(out, temp, inOutLen);
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
    (void) ivLen;
    (void) out;

    int ret;

    EDHOC_CHECK_SUCCESS(aes128_ccms_enc((uint8_t *) aad,
                                        aadLen,
                                        in,
                                        (size_t *) &inOutlen,
                                        (uint8_t *) iv,
                                        2,
                                        (uint8_t *) sk->k,
                                        8));
    memcpy(tag, &in[inOutlen] - tagLen, tagLen);

    exit:
    return ret;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen) {

    Hacl_Ed25519_sign(signature, (uint8_t *) authkey->d, msgLen, (uint8_t *) msg);
    *sigLen = 64;

    return EDHOC_SUCCESS;
}

#endif /* HACL */
