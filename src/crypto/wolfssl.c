
#include "edhoc/cose.h"
#include "edhoc/edhoc.h"
#include "crypto.h"

#if defined(WOLFSSL)

// do not remove
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ed25519.h>

int crypt_gen_keypair(cose_curve_t crv, cose_key_t *key) {
    int ret;
    (void) crv;

    WC_RNG rng;
    curve25519_key _key;

    wc_InitRng(&rng); // initialize random number generator
    wc_curve25519_init(&_key);

    EDHOC_CHECK_SUCCESS(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &_key));

    key->dLen = COSE_ECC_KEY_SIZE;
    key->xLen = COSE_ECC_KEY_SIZE;
    wc_curve25519_export_key_raw(&_key, key->d, (word32 *) &key->dLen, key->x, (word32 *) &key->xLen);

    exit:
    wc_FreeRng(&rng);
    return ret;
}


int crypt_copy_hash_context(sha_ctx_t *dstCtx, sha_ctx_t *srcCtx) {
    return wc_Sha256Copy(srcCtx, dstCtx);
}

int crypt_hash_init(sha_ctx_t *ctx) {
    if (wc_InitSha256(ctx) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_update(sha_ctx_t *ctx, const uint8_t *in, size_t ilen) {
    if (wc_Sha256Update(ctx, in, ilen) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_finish(sha_ctx_t *ctx, uint8_t *out) {
    if (wc_Sha256Final(ctx, out) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

void crypt_hash_free(sha_ctx_t *ctx) {
    wc_Sha256Free(ctx);
}

int crypt_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, uint8_t *out, size_t olen) {
    int ret;

    ret = EDHOC_ERR_CRYPTO;

    if (wc_HKDF_Expand(SHA256, prk, EDHOC_DIGEST_SIZE, info, infoLen, out, olen) != EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CRYPTO;
        goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

/**
 * @brief Load a private COSE key over Curve25519 into a curve25519_key structure
 *
 * @param[in] private_key   COSE key holding the private bytes
 * @param[out] d            An initialized mbedtls_mpi structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 */
static int load_private_key_from_cose_key(const cose_key_t *private_key, curve25519_key *d) {
    if (private_key == NULL)
        return EDHOC_ERR_CRYPTO;

    if (wc_curve25519_import_private_ex(private_key->d, private_key->dLen, d, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

/**
 * @brief Load a public COSE key over Curve25519 into a curve25519_key structure
 *
 * @param[in] private_key   COSE key holding the private bytes
 * @param[out] d            An initialized mbedtls_mpi structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 */
static int load_public_key_from_cose_key(const cose_key_t *public_key, curve25519_key *Q) {
    if (public_key == NULL)
        return EDHOC_ERR_CRYPTO;

    if (wc_curve25519_check_public(public_key->x, public_key->xLen, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    if (wc_curve25519_import_public_ex(public_key->x, public_key->xLen, Q, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
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

    int ret;

    word32 key_size = COSE_ECC_KEY_SIZE;

    curve25519_key d;
    curve25519_key Q;

    wc_curve25519_init(&d);
    wc_curve25519_init(&Q);

    ret = EDHOC_ERR_CRYPTO;

    // check if the groups (mismatch curves when doing static DH key (Ed25519) * ephemeral key (X25519)
    if (pk->kty != sk->kty /* || pk->crv != sk->crv */) {
        ret = EDHOC_ERR_INVALID_KEY;
        goto exit;
    }

    if (sk->dLen == 0 && sk->xLen == 0) {
        ret = EDHOC_ERR_INVALID_KEY;
        goto exit;
    }

    if (sk->dLen == 0 || load_private_key_from_cose_key(sk, &d) != EDHOC_SUCCESS) {
        goto exit;
    }

    if (pk->xLen == 0 || load_public_key_from_cose_key(pk, &Q) != EDHOC_SUCCESS) {
        goto exit;
    }

    if (wc_curve25519_shared_secret_ex(&d, &Q, out, &key_size, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:

    wc_curve25519_free(&d);
    wc_curve25519_free(&Q);

    return ret;
}

int crypt_derive_prk(const cose_key_t *sk,
                     const cose_key_t *pk,
                     const uint8_t *salt,
                     size_t saltLen,
                     uint8_t *prk) {
    int ret;
    Hmac hmac;

    uint8_t secret[EDHOC_DH_SECRET_SIZE];

    ret = EDHOC_ERR_CRYPTO;
    memset(&hmac, 0, sizeof(hmac));

    EDHOC_CHECK_SUCCESS(crypt_ecdh(sk, pk, secret));

    if (wc_HmacSetKey(&hmac, SHA256, salt, saltLen) != EDHOC_SUCCESS)
        goto exit;

    if (wc_HmacUpdate(&hmac, secret, 32) != EDHOC_SUCCESS)
        goto exit;

    if (wc_HmacFinal(&hmac, prk))
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    wc_HmacFree(&hmac);
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
    int ret;
    Aes aes;

    ret = EDHOC_ERR_CRYPTO;

    if (wc_AesCcmSetKey(&aes, sk->k, sk->kLen) != EDHOC_SUCCESS)
        goto exit;

    if (wc_AesCcmDecrypt(&aes, out, in, inOutLen, iv, ivLen, tag, tagLen, aad, aadLen) != EDHOC_SUCCESS)
        goto exit;


    ret = EDHOC_SUCCESS;
    exit:
    wc_AesFree(&aes);
    return ret;
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

    int ret;
    Aes aes;

    ret = EDHOC_ERR_CRYPTO;

    if (wc_AesCcmSetKey(&aes, sk->k, sk->kLen) != EDHOC_SUCCESS)
        goto exit;

    if (wc_AesCcmEncrypt(&aes, out, in, inOutLen, iv, ivLen, tag, tagLen, aad, aadLen) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    wc_AesFree(&aes);
    return ret;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen) {

    int ret;

    ed25519_key sk;
    uint8_t pk[COSE_ECC_KEY_SIZE];

    wc_ed25519_init(&sk);

    ret = EDHOC_ERR_CRYPTO;

    if (wc_ed25519_import_private_only(authkey->d, authkey->dLen, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_make_public(&sk, pk, COSE_ECC_KEY_SIZE) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_import_private_key(authkey->d, authkey->dLen, pk, COSE_ECC_KEY_SIZE, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_sign_msg(msg, msgLen, signature, (word32 *) sigLen, &sk) != EDHOC_SUCCESS)
        goto exit;

    *sigLen = 64;

    ret = EDHOC_SUCCESS;
    exit:
    wc_ed25519_free(&sk);
    return ret;
}


#endif /* WOLFSSL */
