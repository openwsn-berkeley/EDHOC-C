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

int edhoc_conf_setup(edhoc_conf_t *conf,
                     edhoc_role_t role,
                     rng_cb_t f_rng,
                     void *p_rng,
                     cred_cb_t cred_cb,
                     ad_cb_t ad1_cb,
                     ad_cb_t ad2_cb,
                     ad_cb_t ad3_cb) {

    if (role != EDHOC_IS_INITIATOR && role != EDHOC_IS_RESPONDER) {
        return EDHOC_ERR_INVALID_ROLE;
    }

    conf->role = role;

#if defined(MBEDTLS)
    if (f_rng == NULL)
        return EDHOC_ERR_RNG;
#endif

    conf->f_rng = f_rng;
    conf->p_rng = p_rng;

    // if NULL authentication of the key exchange will be skipped
    conf->get_edhoc_creds = cred_cb;

    // callback functions to fetch additional data that needs to be piggybacked on the key exchange
    conf->ad1 = ad1_cb;
    conf->ad2 = ad2_cb;
    conf->ad3 = ad3_cb;

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
 * @brief Compute the EDHOC mac2 value
 *
 * @param ctx[in]   EDHOC context structure
 *
 * @return On success, returns EDHOC_SUCCESS
 * @return On failure a negative value (EDHOC_ERR_ILLEGAL_CIPHERSUITE, EDHOC_ERR_CRYPTO, ...)
 */
static int compute_signature_or_mac23(edhoc_ctx_t *ctx,
                                      const uint8_t *k_23m,
                                      const uint8_t *iv_23m,
                                      ad_cb_t ad23,
                                      const uint8_t *th23,
                                      uint8_t *out) {
    int ret;

    cose_curve_t crv;
    cose_algo_t aead;
    ssize_t enc_structure_len, ext_aad_len, tag_len, size, written;
    uint8_t m23_or_a23m_buf[EDHOC_MAX_M23_OR_A23M_LEN];

    size = 0;

    if ((crv = edhoc_sign_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_CURVE_UNAVAILABLE;

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    if ((tag_len = cose_tag_len_from_alg(aead)) < 0)
        return EDHOC_ERR_AEAD_UNKNOWN;

    if ((ext_aad_len = cose_ext_aad_encode(
            th23,
            ctx->conf->certificate.cert,
            ctx->conf->certificate.cert_len,
            NULL,
            m23_or_a23m_buf,
            EDHOC_MAX_M23_OR_A23M_LEN)) < EDHOC_SUCCESS) {
        ret = ext_aad_len;  // store error code and exit
        goto exit;
    }

    // move to the back of the buffer
    memcpy(m23_or_a23m_buf + EDHOC_MAX_M23_OR_A23M_LEN - ext_aad_len, m23_or_a23m_buf, ext_aad_len);

    if ((enc_structure_len = cose_enc_structure_encode(ctx->conf->cred_id,
                                                       ctx->conf->cred_id_len,
                                                       m23_or_a23m_buf + EDHOC_MAX_M23_OR_A23M_LEN - ext_aad_len,
                                                       ext_aad_len,
                                                       m23_or_a23m_buf,
                                                       EDHOC_MAX_M23_OR_A23M_LEN)) < EDHOC_SUCCESS) {
        ret = enc_structure_len;
        goto exit;
    }

    uint8_t ciphertext, plaintext;
    EDHOC_CHECK_SUCCESS(crypt_encrypt_aead(aead,
                                           k_23m,
                                           iv_23m,
                                           m23_or_a23m_buf,
                                           enc_structure_len,
                                           &plaintext,
                                           &ciphertext,
                                           0,
                                           out));

    // here we start reusing the m2_or_a2m buffer
    if (*ctx->method == EDHOC_AUTH_SIGN_SIGN || *ctx->method == EDHOC_AUTH_STATIC_SIGN) {

        // clear for debugging purposes
        memset(m23_or_a23m_buf, 0, sizeof(m23_or_a23m_buf));
        if ((ext_aad_len = cose_ext_aad_encode(
                th23,
                ctx->conf->certificate.cert,
                ctx->conf->certificate.cert_len,
                ad23,
                m23_or_a23m_buf,
                sizeof(m23_or_a23m_buf))) < EDHOC_SUCCESS) {
            ret = ext_aad_len;  // store error code and exit
            goto exit;
        }

        // move to the back of the buffer
        memcpy(m23_or_a23m_buf + EDHOC_MAX_M23_OR_A23M_LEN - ext_aad_len, m23_or_a23m_buf, ext_aad_len);

        ret = EDHOC_ERR_CBOR_ENCODING;
        CBOR_CHECK_RET(cbor_create_array(m23_or_a23m_buf, 4, size, sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_string("Signature1", m23_or_a23m_buf, size, sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(ctx->conf->cred_id, ctx->conf->cred_id_len, m23_or_a23m_buf, size,
                                               sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(m23_or_a23m_buf + EDHOC_MAX_M23_OR_A23M_LEN - ext_aad_len, ext_aad_len,
                                               m23_or_a23m_buf, size, sizeof(m23_or_a23m_buf)));

        CBOR_CHECK_RET(cbor_array_append_bytes(out, tag_len, m23_or_a23m_buf, size, sizeof(m23_or_a23m_buf)));

        // compute signature
        crypt_compute_signature(crv,
                                &ctx->conf->auth_key,
                                m23_or_a23m_buf,
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
        uint8_t *out,
        size_t olen) {

    ssize_t ret;
    cose_curve_t crv;

    if ((ctx->session.selected_suite = (cipher_suite_t *) edhoc_select_suite(suite)) == NULL)
        ret = EDHOC_ERR_INVALID_CIPHERSUITE;

    if ((ctx->method = (method_t *) edhoc_select_auth_method(method)) == NULL)
        return EDHOC_ERR_INVALID_AUTH_METHOD;

    ctx->correlation = correlation;

    if ((crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_CURVE_UNAVAILABLE;

    // if not already initialized, generate and load ephemeral key
    if (ctx->local_eph_key.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_SUCCESS(crypt_gen_keypair(crv, ctx->conf->f_rng, ctx->conf->p_rng, &ctx->local_eph_key));
    }

    if ((ret = edhoc_msg1_encode(ctx->correlation,
                                 *ctx->method,
                                 *ctx->session.selected_suite,
                                 &ctx->local_eph_key,
                                 ctx->session.cidi,
                                 ctx->session.cidi_len,
                                 ctx->conf->ad1,
                                 out,
                                 olen)) < EDHOC_SUCCESS) {
        goto exit;
    }

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
static ssize_t create_p2e_or_p3ae(edhoc_ctx_t *ctx, uint8_t *signature_23, uint8_t *out, size_t olen) {
    ssize_t size, written;

    size = 0;

    if (ctx->conf->cred_id_len > olen)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    // copy the CBOR encoding from CRED_ID to the output buffer
    memcpy(out, ctx->conf->cred_id, ctx->conf->cred_id_len);
    size += ctx->conf->cred_id_len;

    // append CBOR encoding of signature_2
    CBOR_CHECK_RET(cbor_bytes_encode(signature_23, COSE_MAX_SIGNATURE_LEN, out, size, olen));

    exit:
    return size;
}

/**
 * @brief   Creates the associated data for the outer COSE_Encrypt0 structure in EDHOC message 3
 *
 * @param[in] th3       Transcript hash 3
 * @param[out] out      Output buffer for the result
 * @param[in] olen      Maximum capacity of @p out
 *
 * @return  On success returns the size of A_3ae
 * @return On failure a negative value (i.e., EDHOC_ERR_CBOR_ENCODING, ...)
 */
static ssize_t create_a3ae(const uint8_t *th3, uint8_t *out, size_t olen) {
    ssize_t ret;
    ssize_t size, written;

    size = 0;
    ret = EDHOC_ERR_CBOR_ENCODING;

    CBOR_CHECK_RET(cbor_create_array(out, 3, size, olen));
    CBOR_CHECK_RET(cbor_array_append_string("Encrypt0", out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(NULL, 0, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(th3, COSE_DIGEST_LEN, out, size, olen));

    ret = size;
    exit:
    return ret;
}

ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx,
                          const uint8_t *msg2_buf,
                          size_t msg2_len,
                          uint8_t *out,
                          size_t olen) {
    int ret;
    ssize_t data3_len, size, written, p3ae_len, a3ae_len, key_len, iv_len, tag_len;
    cose_curve_t crv;
    cose_algo_t aead;
    uint8_t k3m_or_k3ae_buf[EDHOC_MAX_K23M_LEN], iv3m_or_iv3ae_buf[EDHOC_MAX_IV23M_LEN], k2e_buf[EDHOC_MAX_PAYLOAD_LEN];
    uint8_t cbor_enc_buf[EDHOC_MAX_PAYLOAD_LEN + 2], a_3ae[EDHOC_MAX_A3AE_LEN], tag[EDHOC_MAX_AUTH_TAG_LEN];
    uint8_t signature_or_mac3_buf[EDHOC_MAX_MAC_OR_SIG23_LEN];

#if defined(MBEDTLS)
    mbedtls_sha256_context transcript_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 transcript_ctx;
#else
#error "No cryptographic backend selected"
#endif

    if ((crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    if ((key_len = cose_key_len_from_alg(aead)) < 0)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    if ((iv_len = cose_iv_len_from_alg(aead)) < 0)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    if ((tag_len = cose_tag_len_from_alg(aead)) < 0)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    EDHOC_CHECK_SUCCESS(edhoc_msg2_decode(ctx, msg2_buf, msg2_len));

    // Start computation transcript hash 2
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));

    EDHOC_CHECK_SIZE(edhoc_msg1_encode(ctx->correlation,
                                       *ctx->method,
                                       *ctx->session.selected_suite,
                                       &ctx->local_eph_key,
                                       ctx->session.cidi,
                                       ctx->session.cidi_len,
                                       ctx->conf->ad1,
                                       out,
                                       olen));

    // update transcript context with EHDOC message 1
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, out, ret));

    // generate data_2
    EDHOC_CHECK_SIZE(edhoc_data2_encode(ctx->correlation,
                                        ctx->session.cidi,
                                        ctx->session.cidi_len,
                                        ctx->session.cidr,
                                        ctx->session.cidr_len,
                                        &ctx->remote_eph_key,
                                        out,
                                        olen));

    // update transcript context with EHDOC message 1
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, out, ret));

    // store th_2 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_2));

    // compute the shared secret
    EDHOC_CHECK_SUCCESS(crypt_compute_ecdh(crv,
                                           &ctx->local_eph_key,
                                           &ctx->remote_eph_key,
                                           ctx->conf->f_rng,
                                           ctx->conf->p_rng,
                                           ctx->secret));

    EDHOC_CHECK_SUCCESS(crypt_compute_prk2e(ctx->secret, NULL, 0, ctx->prk_2e));
    EDHOC_CHECK_SUCCESS(crypt_compute_prk3e2m(ctx->conf->role, *ctx->method, ctx->prk_2e, ctx->secret, ctx->prk_3e2m));

    EDHOC_CHECK_SIZE(crypt_edhoc_kdf(aead, ctx->prk_2e, ctx->th_2, "K_2e", k2e_buf, ctx->ct_or_pld_2_len));

    if ((data3_len = edhoc_data3_encode(ctx->correlation,
                                        ctx->session.cidr,
                                        ctx->session.cidr_len,
                                        out,
                                        olen)) < EDHOC_SUCCESS) {
        ret = data3_len;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(
            crypt_compute_prk4x3m(ctx->conf->role, *ctx->method, ctx->secret, ctx->prk_3e2m, ctx->prk_4x3m));

    // Start computation transcript hash 3
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));

    // update transcript with th_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_2,
                                     COSE_DIGEST_LEN,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_2,
                                     ctx->ct_or_pld_2_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // update transcript with data_3
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, out, data3_len));

    // store th_3 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_3));

    // XOR decryption P_2e XOR K_2e
    for (size_t i = 0; i < ctx->ct_or_pld_2_len; i++) {
        ctx->ct_or_pld_2[i] = ctx->ct_or_pld_2[i] ^ k2e_buf[i];
    }

    EDHOC_CHECK_SUCCESS(edhoc_p2e_decode(ctx->ct_or_pld_2, ctx->ct_or_pld_2_len));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "K_3m", k3m_or_k3ae_buf, key_len));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "IV_3m", iv3m_or_iv3ae_buf, iv_len));

    EDHOC_CHECK_SUCCESS(compute_signature_or_mac23(ctx,
                                                   k3m_or_k3ae_buf,
                                                   iv3m_or_iv3ae_buf,
                                                   ctx->conf->ad3,
                                                   ctx->th_3,
                                                   signature_or_mac3_buf));

    // compute P_2e and write it to the output buffer
    if ((p3ae_len = create_p2e_or_p3ae(ctx, signature_or_mac3_buf, ctx->ct_or_pld_3, EDHOC_MAX_PAYLOAD_LEN)) <
        EDHOC_SUCCESS) {
        ret = p3ae_len;
        goto exit;
    }

    if ((a3ae_len = create_a3ae(ctx->th_3, a_3ae, EDHOC_MAX_A3AE_LEN)) < EDHOC_SUCCESS) {
        ret = a3ae_len;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "K_3ae", k3m_or_k3ae_buf, key_len));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "IV_3ae", iv3m_or_iv3ae_buf, iv_len));

    EDHOC_CHECK_SUCCESS(crypt_encrypt_aead(aead,
                                           k3m_or_k3ae_buf,
                                           iv3m_or_iv3ae_buf,
                                           a_3ae,
                                           a3ae_len,
                                           ctx->ct_or_pld_3,
                                           ctx->ct_or_pld_3,
                                           p3ae_len,
                                           tag));

    // copy the tag
    if (tag_len + p3ae_len > EDHOC_MAX_PAYLOAD_LEN) {
        ret = EDHOC_ERR_BUFFER_OVERFLOW;
        goto exit;
    } else {
        memcpy(ctx->ct_or_pld_3 + p3ae_len, &tag, tag_len);
        ctx->ct_or_pld_3_len = p3ae_len + tag_len;
    }

    // on success ret will contain the size of the EDHOC message_3
    EDHOC_CHECK_SIZE(edhoc_msg3_encode(out, data3_len, ctx->ct_or_pld_3, ctx->ct_or_pld_3_len, out, olen));

    exit:
    crypt_hash_free(&transcript_ctx);
    return ret;
}

ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx,
                          const uint8_t *msg1_buf,
                          size_t msg1_len,
                          uint8_t *out,
                          size_t olen) {
    ssize_t ret, key_len, iv_len;
    cose_curve_t crv;
    cose_algo_t aead;
    ssize_t data2_len, p2e_len;

    // temporary buffers
    uint8_t k2e_buf[EDHOC_MAX_PAYLOAD_LEN];
    uint8_t signature_or_mac2_buf[EDHOC_MAX_MAC_OR_SIG23_LEN];
    uint8_t k2m_buf[EDHOC_MAX_K23M_LEN], iv2m_buf[EDHOC_MAX_IV23M_LEN];

#if defined(MBEDTLS)
    // always SHA-256 (only hash algorithm supported by the EDHOC cipher suites)
    mbedtls_sha256_context transcript_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 transcript_ctx;
#else
#error "No cryptographic backend selected"
#endif

    // decode message 1
    EDHOC_CHECK_SUCCESS(edhoc_msg1_decode(ctx, msg1_buf, msg1_len));

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    if ((crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite)) == COSE_EC_NONE)
        return EDHOC_ERR_CURVE_UNAVAILABLE;

    if ((key_len = cose_key_len_from_alg(aead)) < 0)
        return EDHOC_ERR_AEAD_UNKNOWN;

    if ((iv_len = cose_iv_len_from_alg(aead)) < 0)
        return EDHOC_ERR_AEAD_UNKNOWN;

    // if not already initialized, generate and load ephemeral key
    if (ctx->local_eph_key.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_SUCCESS(crypt_gen_keypair(crv, ctx->conf->f_rng, ctx->conf->p_rng, &ctx->local_eph_key));
    }

    // generate data_2
    if ((data2_len = edhoc_data2_encode(ctx->correlation,
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

    // compute transcript hash 2: TH_2 = H ( msg1, data_2 )
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, msg1_buf, msg1_len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, out, data2_len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_2));

    // compute the shared secret
    EDHOC_CHECK_SUCCESS(crypt_compute_ecdh(crv,
                                           &ctx->local_eph_key,
                                           &ctx->remote_eph_key,
                                           ctx->conf->f_rng,
                                           ctx->conf->p_rng,
                                           ctx->secret));

    EDHOC_CHECK_SUCCESS(crypt_compute_prk2e(ctx->secret, NULL, 0, ctx->prk_2e));
    EDHOC_CHECK_SUCCESS(crypt_compute_prk3e2m(ctx->conf->role, *ctx->method, ctx->prk_2e, ctx->secret, ctx->prk_3e2m));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->th_2, "K_2m", k2m_buf, key_len));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->th_2, "IV_2m", iv2m_buf, iv_len));

    EDHOC_CHECK_SUCCESS(compute_signature_or_mac23(ctx,
                                                   k2m_buf,
                                                   iv2m_buf,
                                                   ctx->conf->ad2,
                                                   ctx->th_2,
                                                   signature_or_mac2_buf));

    // compute P_2e and write it to the output buffer
    if ((p2e_len = create_p2e_or_p3ae(ctx, signature_or_mac2_buf, ctx->ct_or_pld_2, EDHOC_MAX_PAYLOAD_LEN)) <
        EDHOC_SUCCESS) {
        ret = p2e_len;
        goto exit;
    }

    if (p2e_len > EDHOC_MAX_PAYLOAD_LEN) {
        ret = EDHOC_ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_2e, ctx->th_2, "K_2e", k2e_buf, p2e_len));

    // XOR encryption P_2e XOR K_2e
    for (size_t i = 0; i < (size_t) p2e_len; i++) {
        ctx->ct_or_pld_2[i] = ctx->ct_or_pld_2[i] ^ k2e_buf[i];
    }
    ctx->ct_or_pld_2_len = p2e_len;

    // when successful 'ret' will contain the size of EDHOC message_2
    EDHOC_CHECK_SIZE(edhoc_msg2_encode(out, data2_len, ctx->ct_or_pld_2, ctx->ct_or_pld_2_len, out, olen));

    exit:
    crypt_hash_free(&transcript_ctx);
    return ret;
}

int edhoc_exporter(edhoc_ctx_t* ctx, const char* label, size_t length, uint8_t* out, size_t olen){
    int ret;
    cose_algo_t aead;

    if (olen < length)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    if ((aead = edhoc_app_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_4, label, out, length));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_init_finalize(edhoc_ctx_t *ctx) {
    int ret;
    ssize_t size, written;
    uint8_t cbor_enc_buf[EDHOC_MAX_PAYLOAD_LEN + 2];

#if defined(MBEDTLS)
    mbedtls_sha256_context transcript_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 transcript_ctx;
#else
#error "No cryptographic backend selected"
#endif

    size = 0;

    // before decryption of ciphertext_3, start computation TH_4
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));

    // update transcript with th_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_3,
                                     COSE_DIGEST_LEN,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_3,
                                     ctx->ct_or_pld_3_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // store th_4 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_4));

    exit:
    return ret;
}

int edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *msg3_buf, size_t msg3_len) {
    int ret;
    cose_algo_t aead;
    ssize_t size, written, data3_len, a3ae_len, key_len, iv_len, tag_len;
    uint8_t cbor_enc_buf[EDHOC_MAX_PAYLOAD_LEN + 2], k3m_or_k3ae_buf[EDHOC_MAX_K23M_LEN],
            iv3m_or_iv3ae_buf[EDHOC_MAX_IV23M_LEN], a_3ae[EDHOC_MAX_A3AE_LEN];

#if defined(MBEDTLS)
    mbedtls_sha256_context transcript_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 transcript_ctx;
#else
#error "No cryptographic backend selected"
#endif

    if ((aead = edhoc_aead_from_suite(*ctx->session.selected_suite)) == COSE_ALGO_NONE)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    if ((key_len = cose_key_len_from_alg(aead)) < 0)
        return EDHOC_ERR_AEAD_UNKNOWN;

    if ((iv_len = cose_iv_len_from_alg(aead)) < 0)
        return EDHOC_ERR_AEAD_UNKNOWN;

    if ((tag_len = cose_tag_len_from_alg(aead)) < 0)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    // decode message 1
    EDHOC_CHECK_SUCCESS(edhoc_msg3_decode(ctx, msg3_buf, msg3_len));

    // compute prk_4x3m
    EDHOC_CHECK_SUCCESS(
            crypt_compute_prk4x3m(ctx->conf->role, *ctx->method, ctx->secret, ctx->prk_3e2m, ctx->prk_4x3m));

    // Start computation transcript hash 3
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));

    // update transcript with th_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_2,
                                     COSE_DIGEST_LEN,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_2,
                                     ctx->ct_or_pld_2_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    if ((data3_len = edhoc_data3_encode(ctx->correlation,
                                        ctx->session.cidr,
                                        ctx->session.cidr_len,
                                        cbor_enc_buf,
                                        sizeof(cbor_enc_buf))) < EDHOC_SUCCESS) {
        ret = data3_len;
        goto exit;
    }

    // update transcript with data 3
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, data3_len));

    // store th_3 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_3));

    if ((a3ae_len = create_a3ae(ctx->th_3, a_3ae, EDHOC_MAX_A3AE_LEN)) < EDHOC_SUCCESS) {
        ret = a3ae_len;
        goto exit;
    }

    // before decryption of ciphertext_3, start computation TH_4
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&transcript_ctx));

    // update transcript with th_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_3,
                                     COSE_DIGEST_LEN,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_3,
                                     ctx->ct_or_pld_3_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&transcript_ctx, cbor_enc_buf, size));

    // store th_4 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&transcript_ctx, ctx->th_4));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "K_3ae", k3m_or_k3ae_buf, key_len));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_4x3m, ctx->th_3, "IV_3ae", iv3m_or_iv3ae_buf, iv_len));

    // decrypt ciphertext_3
    EDHOC_CHECK_SUCCESS(crypt_decrypt_aead(aead,
                                           k3m_or_k3ae_buf,
                                           iv3m_or_iv3ae_buf,
                                           a_3ae,
                                           a3ae_len,
                                           ctx->ct_or_pld_3,
                                           ctx->ct_or_pld_3,
                                           ctx->ct_or_pld_3_len - tag_len,
                                           &ctx->ct_or_pld_3[ctx->ct_or_pld_3_len - tag_len]));

    EDHOC_CHECK_SUCCESS(edhoc_p3ae_decode(ctx->ct_or_pld_3, ctx->ct_or_pld_3_len - tag_len));

    exit:
    return ret;
}


