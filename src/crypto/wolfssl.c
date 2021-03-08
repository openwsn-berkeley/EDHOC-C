
#include "cose.h"
#include "edhoc/edhoc.h"
#include "format.h"
#include "crypto.h"

#if defined(WOLFSSL)

// do not remove
#include <wolfssl/options.h>

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

    // if true, key already initialized
    if (key->kty != COSE_KTY_NONE){
        return EDHOC_SUCCESS;
    }

    EDHOC_CHECK_SUCCESS(wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &_key));

    key->d_len = EDHOC_ECC_KEY_MAX_SIZE;
    key->x_len = EDHOC_ECC_KEY_MAX_SIZE;
    wc_curve25519_export_key_raw(&_key, key->d, (word32 *) &key->d_len, key->x, (word32 *) &key->x_len);

    exit:
    wc_FreeRng(&rng);
    return ret;
}

int crypt_hash_init(hash_ctx_t *ctx) {
    if (wc_InitSha256(&ctx->digest_ctx) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_update(hash_ctx_t *ctx, const uint8_t *in, size_t ilen) {
    if (wc_Sha256Update(&ctx->digest_ctx, in, ilen) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_finish(hash_ctx_t *ctx, uint8_t *out) {
    if (wc_Sha256Final(&ctx->digest_ctx, out) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

void crypt_hash_free(hash_ctx_t *ctx) {
    wc_Sha256Free(&ctx->digest_ctx);
}

int
crypt_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, int length, uint8_t *out) {
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

    if (wc_HKDF_Expand(SHA256, prk, EDHOC_HASH_MAX_SIZE, info_buf, info_len, out, length) != EDHOC_SUCCESS) {
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

    if (wc_curve25519_import_private_ex(private_key->d, private_key->d_len, d, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
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

    if (wc_curve25519_check_public(public_key->x, public_key->x_len, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    if (wc_curve25519_import_public_ex(public_key->x, public_key->x_len, Q, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
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

    word32 key_size = EDHOC_ECC_KEY_MAX_SIZE;

    curve25519_key d;
    curve25519_key Q;

    wc_curve25519_init(&d);
    wc_curve25519_init(&Q);

    ret = EDHOC_ERR_CRYPTO;

    // check if the groups
    if (pk->kty != sk->kty) {
        ret = EDHOC_ERR_CURVE_UNAVAILABLE;
        goto exit;
    }

    if (load_private_key_from_cose_key(sk, &d) != EDHOC_SUCCESS) {
        goto exit;
    }

    if (load_public_key_from_cose_key(pk, &Q) != EDHOC_SUCCESS) {
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
                     size_t salt_len,
                     uint8_t *prk) {
    int ret;
    Hmac hmac;

    uint8_t secret[EDHOC_SHARED_SECRET_MAX_SIZE];

    ret = EDHOC_ERR_CRYPTO;
    memset(&hmac, 0, sizeof(hmac));

    EDHOC_CHECK_SUCCESS(crypt_ecdh(sk, pk, secret));

    if (wc_HmacSetKey(&hmac, SHA256, salt, salt_len) != EDHOC_SUCCESS)
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

    Aes aes;
    int ret, key_len, iv_len, tag_len;
    const aead_info_t *aead_info;

    ret = EDHOC_ERR_CRYPTO;

    aead_info = cose_aead_info_from_id(alg);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_CIPHER_UNAVAILABLE;

    key_len = aead_info->key_length;
    iv_len = aead_info->iv_length;
    tag_len = aead_info->tag_length;

    if (wc_AesCcmSetKey(&aes, key, key_len) != EDHOC_SUCCESS)
        goto exit;

    if (wc_AesCcmDecrypt(&aes,
                         plaintext,
                         ciphertext,
                         ct_pl_len,
                         iv,
                         iv_len,
                         tag,
                         tag_len,
                         aad,
                         aad_len) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    wc_AesFree(&aes);
    return ret;

}

int crypt_encrypt(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *plaintext,
        uint8_t *ciphertext,
        size_t ct_pl_len,
        uint8_t *tag) {

    Aes aes;
    int ret, key_len, iv_len, tag_len;
    const aead_info_t *aead_info;

    ret = EDHOC_ERR_CRYPTO;

    aead_info = cose_aead_info_from_id(alg);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_CIPHER_UNAVAILABLE;

    key_len = aead_info->key_length;
    iv_len = aead_info->iv_length;
    tag_len = aead_info->tag_length;

    if (wc_AesCcmSetKey(&aes, key, key_len) != EDHOC_SUCCESS)
        goto exit;

    if (wc_AesCcmEncrypt(&aes,
                         ciphertext,
                         plaintext,
                         ct_pl_len,
                         iv,
                         iv_len,
                         tag,
                         tag_len,
                         aad,
                         aad_len) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    wc_AesFree(&aes);
    return ret;
}

int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msg_len, uint8_t *signature) {

    int ret;
    ed25519_key sk;
    wc_ed25519_init(&sk);
    size_t sig_len = EDHOC_SIG23_MAX_SIZE;
    uint8_t pk[EDHOC_ECC_KEY_MAX_SIZE];

    ret = EDHOC_ERR_CRYPTO;

    if (wc_ed25519_import_private_only(authkey->d, authkey->d_len, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_make_public(&sk, pk, EDHOC_ECC_KEY_MAX_SIZE) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_import_private_key(authkey->d, authkey->d_len, pk, EDHOC_ECC_KEY_MAX_SIZE, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_sign_msg(msg, msg_len, signature, (word32 *) &sig_len, &sk) != EDHOC_SUCCESS)
        goto exit;

    // store and return the length of the signature
    ret = sig_len;

    exit:
    wc_ed25519_free(&sk);
    return ret;
}

#endif /* WOLFSSL */
