#include <string.h>

#include "edhoc/cipher_suites.h"
#include "edhoc_internal.h"
#include "crypto_internal.h"

#if defined(MBEDTLS)

#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/ccm.h>
#include <mbedtls/ecdsa.h>

/**
 * @brief Map a COSE curve to an MBEDTLS curve
 *
 * @param crv[in]   COSE curve
 *
 * @return On success, An MBEDTLS curve
 * @return On failure, EDHOC_ERR_CURVE_UNAVAILABLE
 */
static int cose_curve_to_mbedtls_curve(cose_curve_t crv) {
    int id;

    switch (crv) {
        case COSE_EC_CURVE_ED25519:
        case COSE_EC_CURVE_X25519:
            id = MBEDTLS_ECP_DP_CURVE25519;
            break;
        case COSE_EC_CURVE_P256:
            id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        default:
            id = EDHOC_ERR_CURVE_UNAVAILABLE;
            break;
    }

    return id;
}

int crypt_gen_keypair(cose_curve_t crv, rng_cb_t f_rng, void *edhoc_rng_context, cose_key_t *key) {
    int ret;
    int grp_id;

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    ret = EDHOC_ERR_CURVE_UNAVAILABLE;

    if ((grp_id = cose_curve_to_mbedtls_curve(crv)) == EDHOC_ERR_CURVE_UNAVAILABLE)
        goto exit;

    if ((mbedtls_ecp_group_load(&grp, grp_id)) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_ERR_RNG;
    if (f_rng == NULL)
        goto exit;

    ret = EDHOC_ERR_KEY_GENERATION;
    if ((mbedtls_ecp_gen_keypair(&grp, &d, &Q, f_rng, edhoc_rng_context)) != EDHOC_SUCCESS)
        goto exit;

    // load the generated key pair in the cose key struct
    ret = EDHOC_ERR_CRYPTO;
    if (mbedtls_ecp_point_write_binary(&grp,
                                       &Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &key->x_len,
                                       key->x,
                                       COSE_MAX_KEY_LEN) != EDHOC_SUCCESS)
        goto exit;

    if (mbedtls_mpi_write_binary(&d, key->d, COSE_MAX_KEY_LEN) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return ret;
}

/**
 * @brief Load a COSE key over Curve25519 into an mbedtls_mpi structure
 *
 * @param[in] private_key   COSE key holding the private bytes
 * @param[out] d            An initialized mbedtls_mpi structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 */
static int load_private_key_from_cose_key(const cose_key_t *private_key, mbedtls_mpi *d) {

    uint8_t temp_buf[COSE_MAX_KEY_LEN];

    if (private_key->d_len > COSE_MAX_KEY_LEN)
        return EDHOC_ERR_CRYPTO;

    memcpy(temp_buf, private_key->d, private_key->d_len);
    temp_buf[0] &= (uint8_t) 0xf8;
    temp_buf[COSE_MAX_KEY_LEN - 1] &= (uint8_t) 0x7f;
    temp_buf[COSE_MAX_KEY_LEN - 1] |= (uint8_t) 0x40;

    if (mbedtls_mpi_read_binary_le(d, temp_buf, private_key->d_len) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    return EDHOC_SUCCESS;
}

/**
 * @brief Load a public COSE key over Curve25519 into an mbedtls_mpi structure
 *
 * @param[in] private_key   COSE key holding the private bytes
 * @param[out] d            An initialized mbedtls_mpi structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 */
static int load_public_key_from_cose_key(const cose_key_t *public_key, mbedtls_ecp_point *Q) {
    int grp_id;
    mbedtls_ecp_group grp;

    grp_id = cose_curve_to_mbedtls_curve(public_key->crv);
    mbedtls_ecp_group_init(&grp);

    if (mbedtls_ecp_group_load(&grp, grp_id) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    if (mbedtls_ecp_point_read_binary(&grp, Q, public_key->x, public_key->x_len) != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;

    return EDHOC_SUCCESS;
}

int
crypt_edhoc_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, uint8_t *out, size_t olen) {
    ssize_t ret;
    uint8_t info_buf[45];
    ssize_t info_len;
    const mbedtls_md_info_t *md_info;

    ret = EDHOC_ERR_CRYPTO;

    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL)
        goto exit;

    if ((info_len = edhoc_info_encode(id, th, label, olen, info_buf, sizeof(info_buf))) < EDHOC_SUCCESS) {
        ret = info_len;     // store the error code and return
        goto exit;
    }

    if (mbedtls_hkdf_expand(md_info, prk, COSE_DIGEST_LEN, info_buf, info_len, out, olen) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_compute_prk2e(const uint8_t *secret, const uint8_t *salt, size_t salt_len, uint8_t *out) {
    int ret;
    ret = EDHOC_ERR_CRYPTO;

    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info;

    mbedtls_md_init(&md_ctx);

    if ((md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)) == NULL)
        goto exit;

    if (mbedtls_md_setup(&md_ctx, md_info, 1) != EDHOC_SUCCESS)
        goto exit;

    if ((mbedtls_md_hmac_starts(&md_ctx, salt, salt_len)) != EDHOC_SUCCESS)
        goto exit;

    if (mbedtls_md_hmac_update(&md_ctx, secret, 32) != EDHOC_SUCCESS)
        goto exit;

    if (mbedtls_md_hmac_finish(&md_ctx, out) != EDHOC_SUCCESS)
        goto exit;

    ret = EDHOC_SUCCESS;
    exit:
    mbedtls_md_free(&md_ctx);
    return ret;
}

int crypt_compute_prk3e2m(
        edhoc_role_t role,
        method_t method,
        uint8_t *prk2e,
        uint8_t shared_secret[32],
        uint8_t *prk3e2m) {
    int ret;

    switch (method) {
        case EDHOC_AUTH_SIGN_SIGN:
        case EDHOC_AUTH_STATIC_SIGN:
            memcpy(prk3e2m, prk2e, COSE_DIGEST_LEN);
            break;
        case EDHOC_AUTH_STATIC_STATIC:
        case EDHOC_AUTH_SIGN_STATIC:
            //TODO: implement static DH
            break;
        default:
            break;
    }

    ret = EDHOC_SUCCESS;
    return ret;
}

int crypt_aead_tag(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *tag) {

    int ret;
    int key_len, iv_len, tag_len;
    mbedtls_ccm_context ctx;

    key_len = cose_key_len_from_alg(alg);
    iv_len = cose_iv_len_from_alg(alg);
    tag_len = cose_tag_len_from_alg(alg);

    mbedtls_ccm_init(&ctx);

    mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 8 * key_len);

    ret = mbedtls_ccm_encrypt_and_tag(&ctx, 0, iv, iv_len, aad, aad_len, NULL, tag, tag, tag_len);

    if (ret != EDHOC_SUCCESS)
        return EDHOC_ERR_CRYPTO;
    else
        return EDHOC_SUCCESS;
}

int crypt_compute_ecdh(
        cose_curve_t crv,
        cose_key_t *private_key,
        cose_key_t *public_key,
        uint8_t out_buf[COSE_MAX_KEY_LEN],
        rng_cb_t f_rng,
        void *p_rng) {

    ssize_t ret;
    int grp_id;

    mbedtls_ecp_group grp;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_mpi d;
    mbedtls_mpi s;
    mbedtls_ecp_point Q;

    // initialize everything
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&s);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecdh_init(&ecdh_ctx);

    // get the appropriate MBEDTLS group identifier
    if ((grp_id = cose_curve_to_mbedtls_curve(crv)) == EDHOC_ERR_CURVE_UNAVAILABLE) {
        ret = EDHOC_ERR_CURVE_UNAVAILABLE;
        goto fail;
    }

    // check if the groups
    if ((crv != private_key->crv || crv != public_key->crv) || (public_key->kty != private_key->kty)) {
        ret = EDHOC_ERR_CRYPTO;
        goto fail;
    }

    if ((mbedtls_ecp_group_load(&grp, grp_id)) != EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CRYPTO;
        goto fail;
    }

    if ((ret = load_private_key_from_cose_key(private_key, &d)) != EDHOC_SUCCESS) {
        goto fail;
    }

    if ((ret = load_public_key_from_cose_key(public_key, &Q)) != EDHOC_SUCCESS) {
        goto fail;
    }

    if ((mbedtls_ecdh_compute_shared(&grp, &s, &Q, &d, f_rng, p_rng)) != EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CRYPTO;
        goto fail;
    }

    if ((ret = mbedtls_mpi_write_binary_le(&s, out_buf, COSE_MAX_KEY_LEN)) != EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CRYPTO;
        goto fail;
    }

    fail:
    return ret;
}

int crypt_hash_init(hash_ctx_t* ctx) {
    int ret;

    ret = EDHOC_ERR_CRYPTO;

    mbedtls_sha256_init(&ctx->digest_ctx);
    EDHOC_CHECK_RET(mbedtls_sha256_starts_ret(&ctx->digest_ctx, 0));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_hash_update(hash_ctx_t* ctx, const uint8_t *in, size_t ilen) {
    int ret;

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(mbedtls_sha256_update_ret(&ctx->digest_ctx, in, ilen));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int crypt_hash_finish(hash_ctx_t* ctx, uint8_t *output) {
    int ret;

    ret = EDHOC_ERR_CRYPTO;

    EDHOC_CHECK_SUCCESS(mbedtls_sha256_finish_ret(&ctx->digest_ctx, output));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

void crypt_hash_free(hash_ctx_t* ctx) {
    mbedtls_sha256_free(&ctx->digest_ctx);
}

int crypt_compute_signature(cose_curve_t crv,
                            cose_key_t *authkey,
                            const uint8_t *digest,
                            size_t digest_len,
                            rng_cb_t f_rng,
                            void *p_rng) {
    // TODO: MBEDTLS does not yet support Ed25519 (?)
    return -1;
    //int ret, grp_id;

    //mbedtls_ecdsa_context ecdsa_ctx;
    //mbedtls_mpi d, s, r;
    //mbedtls_ecp_group grp;

    //mbedtls_ecp_group_init(&grp);
    //mbedtls_ecdsa_init(&ecdsa_ctx);
    //mbedtls_mpi_init(&d);
    //mbedtls_mpi_init(&r);
    //mbedtls_mpi_init(&s);

    //if ((grp_id = cose_curve_to_mbedtls_curve(crv)) == EDHOC_ERR_CURVE_UNAVAILABLE) {
    //    ret = EDHOC_ERR_CURVE_UNAVAILABLE;
    //    goto exit;
    //} else {
    //    mbedtls_ecp_group_load(&grp, grp_id);
    //}

    //if ((ret = load_private_key_from_cose_key(authkey, &d)) != EDHOC_SUCCESS) {
    //    goto exit;
    //}

    //if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, digest, digest_len, f_rng, p_rng) != EDHOC_SUCCESS) {
    //    ret = EDHOC_ERR_CRYPTO;
    //    goto exit;
    //}

    //exit:
    //mbedtls_ecp_group_free(&grp);
    //mbedtls_mpi_free(&d);
    //mbedtls_mpi_free(&s);
    //mbedtls_mpi_free(&r);
    //mbedtls_ecdsa_free(&ecdsa_ctx);
    //return ret;

}

#endif

