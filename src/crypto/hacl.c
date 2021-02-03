#include "cose.h"
#include "edhoc/edhoc.h"
#include "crypto.h"

#if defined(HACL)

#include <EverCrypt_Curve25519.h>
#include <Lib_RandomBuffer_System.h>
#include <Hacl_Hash.h>
#include <edhoc_internal.h>
#include <Hacl_HKDF.h>
#include <cipher_suites.h>
#include <Hacl_Ed25519.h>
#include "ccm.h"

int crypt_gen_keypair(cose_curve_t crv, rng_cb_t f_rng, void *p_rng, cose_key_t *key) {
    (void) f_rng;
    (void) p_rng;

    key->x_len = COSE_MAX_KEY_LEN;

    if (crv == COSE_EC_CURVE_X25519) {
        Lib_RandomBuffer_System_randombytes(key->d, key->d_len);
        Hacl_Curve25519_51_secret_to_public(key->x, key->d);
        key->x_len = COSE_MAX_KEY_LEN;
    } else {
        return EDHOC_ERR_KEY_GENERATION;
    }

    return EDHOC_SUCCESS;
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
}

void crypt_hash_free(hash_ctx_t *ctx) {
    ctx->fill_level = 0;
}

int
crypt_edhoc_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, uint8_t *out, size_t olen) {
    ssize_t ret;
    uint8_t info_buf[EDHOC_MAX_KDF_INFO_LEN];
    ssize_t info_len;

    ret = EDHOC_ERR_CRYPTO;

    // TODO: check if the label length doesn't cause a buffer overflow. If label is too long, it will cause info_buf to
    //  overflow.

    if ((info_len = edhoc_info_encode(id, th, label, olen, info_buf, EDHOC_MAX_MAC_OR_SIG23_LEN)) < EDHOC_SUCCESS) {
        ret = info_len;     // store the error code and return
        goto exit;
    }

    Hacl_HKDF_expand_sha2_256(out, (uint8_t *) prk, COSE_DIGEST_LEN, info_buf, info_len, olen);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_compute_prk2e(const uint8_t *shared_secret, const uint8_t *salt, size_t salt_len, uint8_t *prk_2e) {

    Hacl_HMAC_compute_sha2_256(prk_2e, (uint8_t *) salt, salt_len, (uint8_t *) shared_secret, 32);

    return EDHOC_SUCCESS;
}

int crypt_compute_prk4x3m(edhoc_role_t role,
                          uint8_t method,
                          const uint8_t *shared_secret,
                          const uint8_t *prk_3e2m,
                          uint8_t *prk_4x3m) {
    (void) shared_secret;

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
                          uint8_t method,
                          const uint8_t *prk_2e,
                          const uint8_t *shared_secret,
                          uint8_t *prk_3e2m) {
    (void) shared_secret;

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

int crypt_compute_ecdh(
        cose_curve_t crv,
        cose_key_t *private_key,
        cose_key_t *public_key,
        rng_cb_t f_rng,
        void *p_rng,
        uint8_t *out) {

    (void) crv;
    (void) f_rng;
    (void) p_rng;

    EverCrypt_Curve25519_ecdh(out, private_key->d, public_key->x);

    return EDHOC_SUCCESS;
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

    int ret;
    ret = EDHOC_SUCCESS;
    return ret;

}

int crypt_encrypt_aead(cose_algo_t alg,
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

int crypt_compute_signature(cose_curve_t crv,
                            cose_key_t *authkey,
                            const uint8_t *msg,
                            size_t msg_len,
                            rng_cb_t f_rng,
                            void *p_rng,
                            uint8_t *signature) {
    (void) crv;
    (void) f_rng;
    (void) p_rng;

    Hacl_Ed25519_sign(signature, authkey->d, msg_len, (uint8_t *) msg);

    return EDHOC_SUCCESS;
}

#endif /* HACL */
