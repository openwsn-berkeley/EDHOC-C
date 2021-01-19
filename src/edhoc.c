#include <string.h>

#if defined(MBEDTLS)
#include <mbedtls/sha256.h>
#elif defined(WOLFSSL)

#include <wolfssl/wolfcrypt/sha256.h>

#else
#error "No cryptographic backend selected"
#endif

#include "edhoc/edhoc.h"
#include "edhoc/cipher_suites.h"

#include "crypto_internal.h"
#include "cbor_internal.h"
#include "edhoc_internal.h"

void edhoc_ctx_init(edhoc_ctx_t *ctx) {
    memset(ctx, 0, sizeof(edhoc_ctx_t));
    ctx->correlation = CORR_UNSET;

    cose_key_init(&ctx->local_eph_key);
    cose_key_init(&ctx->remote_eph_key);
}

void edhoc_conf_init(edhoc_conf_t *conf) {
    memset(conf, 0, sizeof(edhoc_ctx_t));

    cose_key_init(&conf->auth_key);
}

void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf) {
    ctx->conf = conf;
}

int edhoc_conf_setup(edhoc_conf_t *conf, edhoc_role_t role, rng_cb_t f_rng, void *p_rng, edhoc_cred_cb_t cb) {
    if (role != EDHOC_IS_INITIATOR && role != EDHOC_IS_RESPONDER) {
        return EDHOC_ERR_ILLEGAL_ROLE;
    }

    conf->role = role;

#if defined(MBEDTLS)
    if (f_rng == NULL)
        return EDHOC_ERR_RNG;
#endif

    conf->f_rng = f_rng;
    conf->p_rng = p_rng;

    // if NULL authentication of the key exchange will be skipped
    conf->edhoc_get_creds = cb;

    return EDHOC_SUCCESS;
}

int edhoc_conf_load_authkey(edhoc_conf_t *conf, const uint8_t *auth_key, size_t auth_key_len) {
    return cose_key_from_cbor(&conf->auth_key, auth_key, auth_key_len);
}

#if defined(EDHOC_DEBUG_ENABLE)

int edhoc_load_ephkey(edhoc_ctx_t *ctx, const uint8_t *eph_key, size_t eph_key_len) {
    return cose_key_from_cbor(&ctx->local_eph_key, eph_key, eph_key_len);
}

#endif

#if defined(EDHOC_AUTH_PUB_KEY)

int edhoc_conf_load_pubkey(edhoc_conf_t *conf, const uint8_t *pub_key, size_t pub_key_len) {
    return cose_key_from_cbor(&conf->pub_key, pub_key, pub_key_len);
    return 0;
}

#endif

#if defined(EDHOC_AUTH_CBOR_CERT)

int edhoc_conf_load_cborcert(edhoc_conf_t *conf, const uint8_t *cbor_cert, size_t cbor_cert_len) {
    return cbor_cert_load_from_cbor(&conf->certificate, cbor_cert, cbor_cert_len);
}

int edhoc_conf_load_cred_id(edhoc_conf_t *conf, const uint8_t *cred_id, size_t cred_id_len) {
    conf->cred_id = cred_id;
    conf->cred_id_len = cred_id_len;

    return EDHOC_SUCCESS;
}

#endif

/**
 * @brief Creates the external additional data for a COSE message.
 *
 * @param th[in]        Transcript hash
 * @param cred[in]      Public credentials (CBOR certificate or public key)
 * @param cred_len[in]  Length of @p cred
 * @param out[out]      Output buffer
 * @param olen[in]      Maximum length of @p out
 *
 * @return On success the size of the external data
 * @return On failure a negative error code (EDHOC_ERR_CBOR_ENCODING, ..)
 */
static ssize_t cose_ext_aad_encode(const uint8_t *th,
                                   const uint8_t *cred,
                                   size_t cred_len,
                                   const uint8_t *ad2,
                                   size_t ad2_len,
                                   uint8_t *out,
                                   size_t olen) {
    ssize_t size, written;

    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(th, COSE_DIGEST_LEN, out, size, olen));
    CBOR_CHECK_RET(cbor_bytes_encode(cred, cred_len, out, size, olen));

    if (ad2 != NULL && ad2_len != 0) {
        CBOR_CHECK_RET(cbor_bytes_encode(ad2, ad2_len, out, size, olen));
    }

    exit:
    return size;
}

/**
 * @brief Create the Enc structure for the COSE Encrypt0 message
 *
 * @param cred_id[in]           Pointer to the credential identifier
 * @param cred_id_len[in]       Length of @p cred_id
 * @param external_aad[in]      Pointer to the external additional data for the COSE Encrypt0 message
 * @param external_aad_len      Length of @p external_aad
 * @param out[out]              Buffer to store the CBOR encoded Enc structure
 * @param olen[in]              Maximum length of @p out
 *
 * @return On success the size of the CBOR encoded Enc structure
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING, ...)
 */
static ssize_t cose_enc_structure_encode(const uint8_t *cred_id,
                                         size_t cred_id_len,
                                         const uint8_t *external_aad,
                                         size_t external_aad_len,
                                         uint8_t *out,
                                         size_t olen) {
    ssize_t size, written;

    size = 0;

    CBOR_CHECK_RET(cbor_create_array(out, 3, 0, olen));
    CBOR_CHECK_RET(cbor_array_append_string("Encrypt0", out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(cred_id, cred_id_len, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(external_aad, external_aad_len, out, size, olen));

    exit:
    return size;
}

/**
 * @brief Compute the EDHOC mac2 value
 *
 * @param ctx[in]   EDHOC context structure
 *
 * @return On success, returns EDHOC_SUCCESS
 * @return On failure a negative value (EDHOC_ERR_ILLEGAL_CIPHERSUITE, EDHOC_ERR_CRYPTO, ...)
 */
static int compute_signature_or_mac2(edhoc_ctx_t *ctx, uint8_t *out, size_t olen) {
    int ret;

    cose_algo_t aead;
    cose_curve_t crv;
    ssize_t key_len, iv_len, enc_structure_len, ext_aad_len, tag_len, size, written;
    uint8_t m2_or_a2m_buf[EDHOC_MAX_M2_OR_A2M_LEN], k2m_buf[EDHOC_MAX_K2M_LEN], iv2m_buf[EDHOC_MAX_IV2M_LEN];

    size = 0;

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    if ((key_len = cose_key_len_from_alg(aead)) < EDHOC_SUCCESS)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    if ((iv_len = cose_iv_len_from_alg(aead)) < EDHOC_SUCCESS)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    if ((crv = edhoc_sign_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_CURVE_UNAVAILABLE;

    if ((tag_len = cose_tag_len_from_alg(aead)) < 0)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    EDHOC_CHECK_RET(crypt_compute_prk2e(ctx->secret, NULL, 0, ctx->prk_2e));
    EDHOC_CHECK_RET(crypt_compute_prk3e2m(ctx->conf->role, *ctx->method, ctx->prk_2e, ctx->secret, ctx->prk_3e2m));
    EDHOC_CHECK_RET(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->transcript_2, "K_2m", k2m_buf, key_len));
    EDHOC_CHECK_RET(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->transcript_2, "IV_2m", iv2m_buf, iv_len));

    if ((ext_aad_len = cose_ext_aad_encode(
            ctx->transcript_2,
            ctx->conf->certificate.cert,
            ctx->conf->certificate.cert_len,
            NULL,
            0,
            m2_or_a2m_buf,
            EDHOC_MAX_M2_OR_A2M_LEN)) < EDHOC_SUCCESS) {
        ret = ext_aad_len;  // store error code and exit
        goto exit;
    }

    // move to the back of the buffer
    memcpy(m2_or_a2m_buf + EDHOC_MAX_M2_OR_A2M_LEN - ext_aad_len, m2_or_a2m_buf, ext_aad_len);

    if ((enc_structure_len = cose_enc_structure_encode(ctx->conf->cred_id,
                                                       ctx->conf->cred_id_len,
                                                       m2_or_a2m_buf + EDHOC_MAX_M2_OR_A2M_LEN - ext_aad_len,
                                                       ext_aad_len,
                                                       m2_or_a2m_buf,
                                                       EDHOC_MAX_M2_OR_A2M_LEN)) < EDHOC_SUCCESS) {
        ret = enc_structure_len;
        goto exit;
    }

    if ((ret = crypt_aead_tag(aead, k2m_buf, iv2m_buf, m2_or_a2m_buf, enc_structure_len, out)) != EDHOC_SUCCESS)
        goto exit;

    // here we start reusing the m2_or_a2m buffer
    if (*ctx->method == EDHOC_AUTH_SIGN_SIGN || *ctx->method == EDHOC_AUTH_STATIC_SIGN) {

        // clear for debugging purposes
        memset(m2_or_a2m_buf, 0, sizeof(m2_or_a2m_buf));
        if ((ext_aad_len = cose_ext_aad_encode(
                ctx->transcript_2,
                ctx->conf->certificate.cert,
                ctx->conf->certificate.cert_len,
                NULL,
                0,
                m2_or_a2m_buf,
                sizeof(m2_or_a2m_buf))) < EDHOC_SUCCESS) {
            ret = ext_aad_len;  // store error code and exit
            goto exit;
        }

        // move to the back of the buffer
        memcpy(m2_or_a2m_buf + EDHOC_MAX_M2_OR_A2M_LEN - ext_aad_len, m2_or_a2m_buf, ext_aad_len);

        ret = EDHOC_ERR_CBOR_ENCODING;
        CBOR_CHECK_RET(cbor_create_array(m2_or_a2m_buf, 4, size, sizeof(m2_or_a2m_buf)));
        CBOR_CHECK_RET(cbor_array_append_string("Signature1", m2_or_a2m_buf, size, sizeof(m2_or_a2m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(ctx->conf->cred_id, ctx->conf->cred_id_len, m2_or_a2m_buf, size,
                                               sizeof(m2_or_a2m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(m2_or_a2m_buf + EDHOC_MAX_M2_OR_A2M_LEN - ext_aad_len, ext_aad_len,
                                               m2_or_a2m_buf, size, sizeof(m2_or_a2m_buf)));

        CBOR_CHECK_RET(cbor_array_append_bytes(out, tag_len, m2_or_a2m_buf, size, sizeof(m2_or_a2m_buf)));

        // compute signature
        crypt_compute_signature(crv,
                                &ctx->conf->auth_key,
                                m2_or_a2m_buf,
                                size,
                                ctx->conf->f_rng,
                                ctx->conf->p_rng,
                                out);
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

static size_t store_conn_id(uint8_t *storage, const uint8_t *conn_id, size_t conn_id_len) {
    if (conn_id_len > EDHOC_MAX_CID_LEN)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    if (conn_id == NULL && conn_id_len != 0)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    memcpy(storage, conn_id, conn_id_len);

    return conn_id_len;
}

int edhoc_session_preset_cidi(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidi_len = store_conn_id(ctx->session.cidi, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

int edhoc_session_preset_cidr(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidr_len = store_conn_id(ctx->session.cidr, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

ssize_t edhoc_create_msg1(
        edhoc_ctx_t *ctx,
        corr_t correlation,
        method_t method,
        cipher_suite_t suite,
        const uint8_t *ad1,
        size_t ad1_len,
        uint8_t *out,
        size_t olen) {

    ssize_t ret;
    cose_curve_t crv;

    if ((ctx->session.selected_suite = (cipher_suite_t *) edhoc_select_suite(suite)) == NULL)
        ret = EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    if ((ctx->method = (method_t *) edhoc_select_auth_method(method)) == NULL)
        return EDHOC_ERR_ILLEGAL_METHOD;

    ctx->correlation = correlation;

    if ((crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_CURVE_UNAVAILABLE;

    // if not already initialized, generate and load ephemeral key
    if (ctx->local_eph_key.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_RET(crypt_gen_keypair(crv, ctx->conf->f_rng, ctx->conf->p_rng, &ctx->local_eph_key));
    }

    EDHOC_CHECK_RET(edhoc_msg1_encode(
            ctx->correlation,
            *ctx->method,
            *ctx->session.selected_suite,
            &ctx->local_eph_key,
            ctx->session.cidi,
            ctx->session.cidi_len,
            ad1,
            ad1_len,
            out,
            olen));

    exit:
    return ret;
}

/**
 * @brief Creates the plaintext CBOR sequence for message 2
 *
 * @param[in] ctx       Pointer to an EDHOC context structure
 * @param[out] out      Pointer to output buffer to store the P_2e CBOR sequence
 * @param olen          Maximum length of @p out
 *
 * @return On success the size of P_2e
 * @return On failure a negative value (i.e., EDHOC_ERR_CBOR_ENCODING, ...)
 */
static ssize_t create_p2e(edhoc_ctx_t *ctx, uint8_t *signature_2, uint8_t *out, size_t olen) {
    ssize_t size, written;

    size = 0;

    if (ctx->conf->cred_id_len > olen)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    // copy the CBOR encoding from CRED_ID to the output buffer
    memcpy(out, ctx->conf->cred_id, ctx->conf->cred_id_len);
    size += ctx->conf->cred_id_len;

    // append CBOR encoding of signature_2
    CBOR_CHECK_RET(cbor_bytes_encode(signature_2, COSE_MAX_SIGNATURE_LEN, out, size, olen));

    exit:
    return size;
}

ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx,
                          const uint8_t *msg1_buf,
                          size_t msg1_len,
                          const uint8_t *aad1,
                          size_t aad1_len,
                          uint8_t *out,
                          size_t olen) {
    ssize_t ret, size, written;
    cose_curve_t crv;
    cose_algo_t aead;
    ssize_t data2_len, p2e_len;

    // temporary buffers
    uint8_t p2e_buf[EDHOC_MAX_P2E_LEN];
    uint8_t k2e_buf[EDHOC_MAX_K2E_LEN];
    uint8_t signature_or_mac2_buf[EDHOC_MAX_MAC_OR_SIG2_LEN];

    (void) aad1_len;
    (void) aad1;

    size = 0;

#if defined(MBEDTLS)
    // always SHA-256 (only hash algorithm supported by the EDHOC cipher suites)
    mbedtls_sha256_context transcript_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 transcript_ctx;
#else
#error "No cryptographic backend selected"
#endif

    // decode message 1
    EDHOC_CHECK_RET(edhoc_msg1_decode(ctx, msg1_buf, msg1_len));

    if ((crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    // if not already initialized, generate and load ephemeral key
    if (ctx->local_eph_key.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_RET(crypt_gen_keypair(crv, ctx->conf->f_rng, ctx->conf->p_rng, &ctx->local_eph_key));
    }

    // generate data_2
    if ((data2_len = edhoc_data2_encode(
            ctx->correlation,
            ctx->session.cidi,
            ctx->session.cidi_len,
            ctx->session.cidr,
            ctx->session.cidr_len,
            &ctx->local_eph_key,
            out,
            olen)) < EDHOC_SUCCESS) {

        ret = data2_len;
        goto exit;
    }

    // compute transcript hash 2
    if ((ret = crypt_hash_init(&transcript_ctx)) != EDHOC_SUCCESS) {
        goto exit;
    }

    // update transcript context with EHDOC message 1
    if ((ret = crypt_hash_update(&transcript_ctx, msg1_buf, msg1_len)) != EDHOC_SUCCESS) {
        goto exit;
    }

    // update transcript context with data_2
    if ((ret = crypt_hash_update(&transcript_ctx, out, data2_len)) != EDHOC_SUCCESS) {
        goto exit;
    }

    // store th_2 in the EDHOC context
    if ((ret = crypt_hash_finish(&transcript_ctx, ctx->transcript_2)) != EDHOC_SUCCESS) {
        goto exit;
    }

    // compute the shared secret
    if ((ret = crypt_compute_ecdh(crv,
                                  &ctx->local_eph_key,
                                  &ctx->remote_eph_key,
                                  ctx->secret,
                                  ctx->conf->f_rng,
                                  ctx->conf->p_rng)) != EDHOC_SUCCESS) {
        goto exit;
    }

    if ((ret = compute_signature_or_mac2(ctx, signature_or_mac2_buf, EDHOC_MAX_MAC_OR_SIG2_LEN)) != EDHOC_SUCCESS)
        goto exit;

    // compute P_2e and write it to the output buffer
    if ((p2e_len = create_p2e(ctx, signature_or_mac2_buf, p2e_buf, EDHOC_MAX_P2E_LEN)) < EDHOC_SUCCESS) {
        ret = p2e_len;
        goto exit;
    }

    if (p2e_len > EDHOC_MAX_K2E_LEN) {
        ret = EDHOC_ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    if ((ret = crypt_edhoc_kdf(aead, ctx->prk_2e, ctx->transcript_2, "K_2e", k2e_buf, p2e_len)) < EDHOC_SUCCESS)
        goto exit;

    // XOR encryption P_2e XOR K_2e
    for (ssize_t i = 0; i < p2e_len; i++) {
        p2e_buf[i] = p2e_buf[i] ^ k2e_buf[i];
    }

    CBOR_CHECK_RET(cbor_bytes_encode(p2e_buf, p2e_len, out + data2_len, size, olen));

    ret = size + data2_len;
    exit:
    crypt_hash_free(&transcript_ctx);
    return ret;
}


