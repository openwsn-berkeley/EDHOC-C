#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "edhoc/cose.h"
#include "edhoc/edhoc.h"
#include "edhoc_internal.h"
#include "edhoc/cipher_suites.h"

#if defined(WOLFSSL)

int crypt_gen_keypair(cose_curve_t crv, rng_cb_t f_rng, void *p_rng, cose_key_t *key) {
    (void) crv;
    (void) f_rng;

    curve25519_key _key;

    wc_curve25519_init(&_key);

    if (p_rng == NULL)
        return EDHOC_ERR_RNG;

    if (wc_curve25519_make_key((WC_RNG *) p_rng, CURVE25519_KEYSIZE, &_key) != EDHOC_SUCCESS)
        return EDHOC_ERR_KEY_GENERATION;

    key->d_len = COSE_MAX_KEY_LEN;
    key->x_len = COSE_MAX_KEY_LEN;
    wc_curve25519_export_key_raw(&_key, key->d, (word32 *) &key->d_len, key->x, (word32 *) &key->x_len);

    return EDHOC_SUCCESS;
}

int crypt_hash_init(void *digest_ctx) {
    if (wc_InitSha256((wc_Sha256 *) digest_ctx) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_update(void *digest_ctx, const uint8_t *in, size_t ilen) {
    if (wc_Sha256Update((wc_Sha256 *) digest_ctx, in, ilen) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_hash_finish(void *digest_ctx, uint8_t *output) {
    if (wc_Sha256Final((wc_Sha256 *) digest_ctx, output) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

void crypt_hash_free(void *digest_ctx) {
    wc_Sha256Free((wc_Sha256 *) digest_ctx);
}

int
crypt_edhoc_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, uint8_t *out, size_t olen) {
    ssize_t ret;
    uint8_t info_buf[EDHOC_MAX_KDF_INFO_LEN];
    ssize_t info_len;

    ret = EDHOC_ERR_CRYPTO;

    if ((info_len = edhoc_info_encode(id, th, label, olen, info_buf, EDHOC_MAX_MAC_OR_SIG23_LEN)) < EDHOC_SUCCESS) {
        ret = info_len;     // store the error code and return
        goto exit;
    }

    if (wc_HKDF_Expand(SHA256, prk, COSE_DIGEST_LEN, info_buf, info_len, out, olen) != EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CRYPTO;
        goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_compute_prk2e(const uint8_t *shared_secret, const uint8_t *salt, size_t salt_len, uint8_t *prk_2e) {
    int ret;
    Hmac hmac;

    ret = EDHOC_ERR_CRYPTO;
    memset(&hmac, 0, sizeof(hmac));

    if (wc_HmacSetKey(&hmac, SHA256, salt, salt_len) != EDHOC_SUCCESS)
        goto exit;

    if (wc_HmacUpdate(&hmac, shared_secret, 32) != EDHOC_SUCCESS)
        goto exit;

    if (wc_HmacFinal(&hmac, prk_2e))
        goto exit;

    ret = EDHOC_SUCCESS;

    exit:
    wc_HmacFree(&hmac);
    return ret;
}

int crypt_compute_prk4x3m(edhoc_role_t role,
                          method_t method,
                          const uint8_t *shared_secret,
                          const uint8_t *prk_3e2m,
                          uint8_t *prk_4x3m) {
    int ret;

    if (role == EDHOC_IS_RESPONDER) {
        switch (method) {
            case EDHOC_AUTH_SIGN_SIGN:
            case EDHOC_AUTH_STATIC_SIGN:
                memcpy(prk_4x3m, prk_3e2m, COSE_DIGEST_LEN);
                break;
            case EDHOC_AUTH_STATIC_STATIC:
            case EDHOC_AUTH_SIGN_STATIC:
                //TODO: implement static DH
                break;
            default:
                break;
        }
    } else { // IS_INITIATOR
        switch (method) {
            case EDHOC_AUTH_SIGN_SIGN:
            case EDHOC_AUTH_SIGN_STATIC:
                memcpy(prk_4x3m, prk_3e2m, COSE_DIGEST_LEN);
                break;
            case EDHOC_AUTH_STATIC_STATIC:
            case EDHOC_AUTH_STATIC_SIGN:
                //TODO: implement static DH
                break;
            default:
                break;
        }
    }

    ret = EDHOC_SUCCESS;
    return ret;
}


int crypt_compute_prk3e2m(edhoc_role_t role,
                          method_t method,
                          const uint8_t *prk_2e,
                          uint8_t *shared_secret,
                          uint8_t *prk_3e2m) {
    int ret;

    if (role == EDHOC_IS_RESPONDER) {

        switch (method) {
            case EDHOC_AUTH_SIGN_SIGN:
            case EDHOC_AUTH_STATIC_SIGN:
                memcpy(prk_3e2m, prk_2e, COSE_DIGEST_LEN);
                break;
            case EDHOC_AUTH_STATIC_STATIC:
            case EDHOC_AUTH_SIGN_STATIC:
                //TODO: implement static DH
                break;
            default:
                break;
        }

    } else { // IS_INITIATOR
        switch (method) {
            case EDHOC_AUTH_SIGN_SIGN:
            case EDHOC_AUTH_SIGN_STATIC:
                memcpy(prk_3e2m, prk_2e, COSE_DIGEST_LEN);
                break;
            case EDHOC_AUTH_STATIC_STATIC:
            case EDHOC_AUTH_STATIC_SIGN:
                //TODO: implement static DH
                break;
            default:
                break;
        }
    }

    ret = EDHOC_SUCCESS;
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

    if (wc_curve25519_check_public(public_key->x, public_key->x_len, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    if (wc_curve25519_import_public_ex(public_key->x, public_key->x_len, Q, EC25519_LITTLE_ENDIAN) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_compute_ecdh(
        cose_curve_t crv,
        cose_key_t *private_key,
        cose_key_t *public_key,
        rng_cb_t f_rng,
        void *p_rng,
        uint8_t *out) {

    int ret;
    (void) f_rng;
    (void) p_rng;

    word32 key_size = COSE_MAX_KEY_LEN;

    curve25519_key d;
    curve25519_key Q;

    wc_curve25519_init(&d);
    wc_curve25519_init(&Q);

    ret = EDHOC_ERR_CRYPTO;

    // check if the groups
    if ((crv != private_key->crv || crv != public_key->crv) || (public_key->kty != private_key->kty)) {
        ret = EDHOC_ERR_CURVE_UNAVAILABLE;
        goto exit;
    }

    if (load_private_key_from_cose_key(private_key, &d) != EDHOC_SUCCESS) {
        goto exit;
    }

    if (load_public_key_from_cose_key(public_key, &Q) != EDHOC_SUCCESS) {
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

int crypt_decrypt_aead(
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

    ret = EDHOC_ERR_CRYPTO;

    key_len = cose_key_len_from_alg(alg);
    iv_len = cose_iv_len_from_alg(alg);
    tag_len = cose_tag_len_from_alg(alg);

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

int crypt_encrypt_aead(
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

    ret = EDHOC_ERR_CRYPTO;

    key_len = cose_key_len_from_alg(alg);
    iv_len = cose_iv_len_from_alg(alg);
    tag_len = cose_tag_len_from_alg(alg);

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

int crypt_compute_signature(cose_curve_t crv,
                            cose_key_t *authkey,
                            const uint8_t *msg,
                            size_t msg_len,
                            rng_cb_t f_rng,
                            void *p_rng,
                            uint8_t *signature) {
    int ret;
    ed25519_key sk;
    wc_ed25519_init(&sk);
    size_t sig_len = COSE_MAX_SIGNATURE_LEN;
    uint8_t pk[COSE_MAX_KEY_LEN];

    ret = EDHOC_ERR_CRYPTO;

    if (wc_ed25519_import_private_only(authkey->d, authkey->d_len, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_make_public(&sk, pk, COSE_MAX_KEY_LEN) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_import_private_key(authkey->d, authkey->d_len, pk, COSE_MAX_KEY_LEN, &sk) != EDHOC_SUCCESS)
        goto exit;

    if (wc_ed25519_sign_msg(msg, msg_len, signature, (word32 *) &sig_len, &sk) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;

    exit:
    wc_ed25519_free(&sk);
    return ret;
}

#endif /* WOLFSSL */
