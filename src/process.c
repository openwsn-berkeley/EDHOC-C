#include "edhoc/edhoc.h"

#include "cipher_suites.h"
#include "crypto.h"
#include "format.h"
#include "cbor.h"

#include "process.h"

ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx, corr_t corr, uint8_t method, uint8_t suite, uint8_t *out, size_t olen) {

    ssize_t ret;
    const method_t *method_info;
    const cipher_suite_t *suite_info;
    cose_curve_t crv;

    suite_info = edhoc_cipher_suite_from_id(suite);
    method_info = edhoc_auth_method_from_id(method);

    if (suite_info != NULL) {
        ctx->session.cipher_suite = suite_info->id;
    } else {
        ret = EDHOC_ERR_INVALID_CIPHERSUITE;
    }

    if (method_info != NULL) {
        ctx->method = method_info->id;
    } else {
        return EDHOC_ERR_INVALID_AUTH_METHOD;
    }

    ctx->correlation = corr;

    crv = suite_info->dh_curve;

    // if not already initialized, generate and load ephemeral key
    if (ctx->local_eph_key.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_SUCCESS(crypt_gen_keypair(crv, ctx->conf->f_rng, ctx->conf->p_rng, &ctx->local_eph_key));
    }

    if ((ret = edhoc_msg1_encode(ctx->correlation,
                                 ctx->method,
                                 ctx->session.cipher_suite,
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
 * @brief Compute the EDHOC signature_or_mac_2 or signature_or_mac_3 structure
 *
 * @param[in] ctx       EDHOC context structure
 * @param[in] k_23m     Symmetric key K_2m or K_3m for authentication tag computation
 * @param[in] iv_23m    Initialization vector IV_2m or IV_3m for authentication tag computation
 * @param[in] th23      Transcript hash TH_2 or TH_3
 * @param[in] ad23      Callback to fetch additional data ad_2 or ad_3
 * @param[out] out      Buffer to store signature or authentication tag (signature_or_mac_2 or signature_or_mac_3)
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value (EDHOC_ERR_ILLEGAL_CIPHERSUITE, EDHOC_ERR_CRYPTO, ...)
 */
int edhoc_create_sig_or_mac23(edhoc_ctx_t *ctx,
                              const uint8_t *k_23m,
                              const uint8_t *iv_23m,
                              const uint8_t *th23,
                              ad_cb_t ad23,
                              uint8_t *out) {
    int ret;

    cose_curve_t crv;
    cose_algo_t aead;
    const cipher_suite_t *suite_info;
    const aead_info_t* aead_info;
    ssize_t enc_structure_len, ext_aad_len, tag_len, size, written;
    uint8_t m23_or_a23m_buf[EDHOC_M23_MAX_SIZE];

    size = 0;

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (suite_info != NULL) {
        crv = suite_info->sign_curve;
        aead = suite_info->aead_algo;
    } else {
        return EDHOC_ERR_CURVE_UNAVAILABLE;
    }

    aead_info = cose_aead_info_from_id(aead);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    tag_len = aead_info->tag_length;

    if ((ext_aad_len = edhoc_cose_external_aad_encode(
            th23,
            ctx->conf->cred.certificate,
            ctx->conf->cred.cert_len,
            NULL,
            m23_or_a23m_buf,
            EDHOC_M23_MAX_SIZE)) < EDHOC_SUCCESS) {
        ret = ext_aad_len;  // store error code and exit
        goto exit;
    }

    // move to the back of the buffer
    memcpy(m23_or_a23m_buf + EDHOC_M23_MAX_SIZE - ext_aad_len, m23_or_a23m_buf, ext_aad_len);

    if ((enc_structure_len = edhoc_cose_enc_struct_encode(ctx->conf->cred_id,
                                                          ctx->conf->cred_id_len,
                                                          m23_or_a23m_buf + EDHOC_M23_MAX_SIZE - ext_aad_len,
                                                          ext_aad_len,
                                                          m23_or_a23m_buf,
                                                          EDHOC_M23_MAX_SIZE)) < EDHOC_SUCCESS) {
        ret = enc_structure_len;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(crypt_encrypt_aead(aead,                // COSE algorithm ID
                                           k_23m,               // encryption key
                                           iv_23m,              // nonce
                                           m23_or_a23m_buf,     // aad
                                           enc_structure_len,   // aad len
                                           out,                 // plaintext
                                           out,                 // ciphertext
                                           0,                   // length of plaintext and ciphertext
                                           out));               // pointer to tag (size depends on selected algorithm)

    // here we start reusing the m2_or_a2m buffer
    if (ctx->method == EDHOC_AUTH_SIGN_SIGN || ctx->method == EDHOC_AUTH_STATIC_SIGN) {

        // clear for debugging purposes
        memset(m23_or_a23m_buf, 0, sizeof(m23_or_a23m_buf));
        if ((ext_aad_len = edhoc_cose_external_aad_encode(
                th23,
                ctx->conf->cred.certificate,
                ctx->conf->cred.cert_len,
                ad23,
                m23_or_a23m_buf,
                sizeof(m23_or_a23m_buf))) < EDHOC_SUCCESS) {
            ret = ext_aad_len;  // store error code and exit
            goto exit;
        }

        // move to the back of the buffer
        memcpy(m23_or_a23m_buf + EDHOC_M23_MAX_SIZE - ext_aad_len, m23_or_a23m_buf, ext_aad_len);

        ret = EDHOC_ERR_CBOR_ENCODING;
        CBOR_CHECK_RET(cbor_create_array(m23_or_a23m_buf, 4, size, sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_string("Signature1", m23_or_a23m_buf, size, sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(ctx->conf->cred_id, ctx->conf->cred_id_len, m23_or_a23m_buf, size,
                                               sizeof(m23_or_a23m_buf)));
        CBOR_CHECK_RET(cbor_array_append_bytes(m23_or_a23m_buf + EDHOC_M23_MAX_SIZE - ext_aad_len, ext_aad_len,
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

ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx,
                          const uint8_t *msg2_buf,
                          size_t msg2_len,
                          uint8_t *out,
                          size_t olen) {

    int ret;
    ssize_t data3_len, size, written, p3ae_len, a3ae_len, key_len, iv_len, tag_len;
    const cipher_suite_t *suite_info;
    const aead_info_t *aead_info;
    cose_curve_t crv;
    cose_algo_t aead;
    hash_ctx_t hash_ctx;
    uint8_t k3m_or_k3ae_buf[EDHOC_K23M_MAX_SIZE], iv3m_or_iv3ae_buf[EDHOC_IV23M_MAX_SIZE], k2e_buf[EDHOC_PAYLOAD_MAX_SIZE];
    uint8_t cbor_enc_buf[EDHOC_PAYLOAD_MAX_SIZE + 2], a_3ae[EDHOC_MAX_A3AE_LEN], tag[EDHOC_AUTH_TAG_MAX_SIZE];
    uint8_t signature_or_mac3_buf[EDHOC_SIG23_MAX_SIZE];

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (suite_info == NULL)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    crv = suite_info->dh_curve;
    aead = suite_info->aead_algo;

    aead_info = cose_aead_info_from_id(aead);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    key_len = aead_info->key_length;
    iv_len = aead_info->iv_length;
    tag_len = aead_info->tag_length;


    EDHOC_CHECK_SUCCESS(edhoc_msg2_decode(ctx, msg2_buf, msg2_len));

    // Start computation transcript hash 2
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));

    EDHOC_CHECK_SIZE(edhoc_msg1_encode(ctx->correlation,
                                       ctx->method,
                                       ctx->session.cipher_suite,
                                       &ctx->local_eph_key,
                                       ctx->session.cidi,
                                       ctx->session.cidi_len,
                                       ctx->conf->ad1,
                                       out,
                                       olen));

    // update transcript context with EHDOC message 1
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, out, ret));

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
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, out, ret));

    // store th_2 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->th_2));

    // compute the shared secret
    EDHOC_CHECK_SUCCESS(crypt_compute_ecdh(crv,
                                           &ctx->local_eph_key,
                                           &ctx->remote_eph_key,
                                           ctx->conf->f_rng,
                                           ctx->conf->p_rng,
                                           ctx->secret));

    EDHOC_CHECK_SUCCESS(crypt_compute_prk2e(ctx->secret, NULL, 0, ctx->prk_2e));
    EDHOC_CHECK_SUCCESS(crypt_compute_prk3e2m(ctx->conf->role, ctx->method, ctx->prk_2e, ctx->secret, ctx->prk_3e2m));

    EDHOC_CHECK_SIZE(crypt_edhoc_kdf(aead, ctx->prk_2e, ctx->th_2, "K_2e", ctx->ct_or_pld_2_len, k2e_buf));

    if ((data3_len = edhoc_data3_encode(ctx->correlation,
                                        ctx->session.cidr,
                                        ctx->session.cidr_len,
                                        out,
                                        olen)) < EDHOC_SUCCESS) {
        ret = data3_len;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(
            crypt_compute_prk4x3m(ctx->conf->role, ctx->method, ctx->secret, ctx->prk_3e2m, ctx->session.prk_4x3m));

    // Start computation transcript hash 3
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));

    // update transcript with th_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_2,
                                     EDHOC_HASH_MAX_SIZE,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_2,
                                     ctx->ct_or_pld_2_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // update transcript with data_3
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, out, data3_len));

    // store th_3 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->th_3));

    // XOR decryption P_2e XOR K_2e
    for (size_t i = 0; i < ctx->ct_or_pld_2_len; i++) {
        ctx->ct_or_pld_2[i] = ctx->ct_or_pld_2[i] ^ k2e_buf[i];
    }

    EDHOC_CHECK_SUCCESS(edhoc_p2e_decode(ctx->ct_or_pld_2, ctx->ct_or_pld_2_len));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "K_3m", key_len, k3m_or_k3ae_buf));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "IV_3m", iv_len, iv3m_or_iv3ae_buf));

    EDHOC_CHECK_SUCCESS(edhoc_create_sig_or_mac23(ctx,
                                                  k3m_or_k3ae_buf,
                                                  iv3m_or_iv3ae_buf,
                                                  ctx->th_3,
                                                  ctx->conf->ad3,
                                                  signature_or_mac3_buf));

    // compute P_2e and write it to the output buffer
    if ((p3ae_len = edhoc_p2e_or_p3ae_encode(ctx,
                                             signature_or_mac3_buf,
                                             ctx->ct_or_pld_3,
                                             EDHOC_PAYLOAD_MAX_SIZE)) < EDHOC_SUCCESS) {
        ret = p3ae_len;
        goto exit;
    }

    if ((a3ae_len = edhoc_a3ae_encode(ctx->th_3, a_3ae, EDHOC_MAX_A3AE_LEN)) < EDHOC_SUCCESS) {
        ret = a3ae_len;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "K_3ae", key_len, k3m_or_k3ae_buf));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "IV_3ae", iv_len, iv3m_or_iv3ae_buf));

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
    if (tag_len + p3ae_len > EDHOC_PAYLOAD_MAX_SIZE) {
        ret = EDHOC_ERR_BUFFER_OVERFLOW;
        goto exit;
    } else {
        memcpy(ctx->ct_or_pld_3 + p3ae_len, tag, tag_len);
        ctx->ct_or_pld_3_len = p3ae_len + tag_len;
    }

    // on success ret will contain the size of the EDHOC message_3
    EDHOC_CHECK_SIZE(edhoc_msg3_encode(out, data3_len, ctx->ct_or_pld_3, ctx->ct_or_pld_3_len, out, olen));

    exit:
    crypt_hash_free(&hash_ctx);
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
    hash_ctx_t hash_ctx;
    const cipher_suite_t *suite_info;
    const aead_info_t *aead_info;

    // temporary buffers
    uint8_t k2e_buf[EDHOC_PAYLOAD_MAX_SIZE];
    uint8_t signature_or_mac2_buf[EDHOC_SIG23_MAX_SIZE];
    uint8_t k2m_buf[EDHOC_K23M_MAX_SIZE], iv2m_buf[EDHOC_IV23M_MAX_SIZE];

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    // decode message 1
    EDHOC_CHECK_SUCCESS(edhoc_msg1_decode(ctx, msg1_buf, msg1_len));

    if (suite_info == NULL)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    aead = suite_info->aead_algo;
    crv = suite_info->dh_curve;

    aead_info = cose_aead_info_from_id(aead);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    key_len = aead_info->key_length;
    iv_len = aead_info->iv_length;

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
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, msg1_buf, msg1_len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, out, data2_len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->th_2));

    // compute the shared secret
    EDHOC_CHECK_SUCCESS(crypt_compute_ecdh(crv,
                                           &ctx->local_eph_key,
                                           &ctx->remote_eph_key,
                                           ctx->conf->f_rng,
                                           ctx->conf->p_rng,
                                           ctx->secret));

    EDHOC_CHECK_SUCCESS(crypt_compute_prk2e(ctx->secret, NULL, 0, ctx->prk_2e));
    EDHOC_CHECK_SUCCESS(crypt_compute_prk3e2m(ctx->conf->role, ctx->method, ctx->prk_2e, ctx->secret, ctx->prk_3e2m));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->th_2, "K_2m", key_len, k2m_buf));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_3e2m, ctx->th_2, "IV_2m", iv_len, iv2m_buf));

    EDHOC_CHECK_SUCCESS(edhoc_create_sig_or_mac23(ctx,
                                                  k2m_buf,
                                                  iv2m_buf,
                                                  ctx->th_2,
                                                  ctx->conf->ad2,
                                                  signature_or_mac2_buf));

    // compute P_2e and write it to the output buffer
    if ((p2e_len = edhoc_p2e_or_p3ae_encode(ctx,
                                            signature_or_mac2_buf,
                                            ctx->ct_or_pld_2,
                                            EDHOC_PAYLOAD_MAX_SIZE)) <
        EDHOC_SUCCESS) {
        ret = p2e_len;
        goto exit;
    }

    if (p2e_len > EDHOC_PAYLOAD_MAX_SIZE) {
        ret = EDHOC_ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->prk_2e, ctx->th_2, "K_2e", p2e_len, k2e_buf));

    // XOR encryption P_2e XOR K_2e
    for (size_t i = 0; i < (size_t) p2e_len; i++) {
        ctx->ct_or_pld_2[i] = ctx->ct_or_pld_2[i] ^ k2e_buf[i];
    }
    ctx->ct_or_pld_2_len = p2e_len;

    // when successful 'ret' will contain the size of EDHOC message_2
    EDHOC_CHECK_SIZE(edhoc_msg2_encode(out, data2_len, ctx->ct_or_pld_2, ctx->ct_or_pld_2_len, out, olen));

    exit:
    crypt_hash_free(&hash_ctx);
    return ret;
}

int edhoc_init_finalize(edhoc_ctx_t *ctx) {
    int ret;
    ssize_t size, written;
    uint8_t cbor_enc_buf[EDHOC_PAYLOAD_MAX_SIZE + 2];

    hash_ctx_t hash_ctx;
    size = 0;

    // before decryption of ciphertext_3, start computation TH_4
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));

    // update transcript with th_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_3,
                                     EDHOC_HASH_MAX_SIZE,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_3,
                                     ctx->ct_or_pld_3_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // store th_4 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->session.th_4));

    exit:
    return ret;
}

int edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *msg3_buf, size_t msg3_len) {
    int ret;
    cose_algo_t aead;
    const cipher_suite_t *suite_info;
    const aead_info_t *aead_info;
    ssize_t size, written, data3_len, a3ae_len, key_len, iv_len, tag_len;
    uint8_t cbor_enc_buf[EDHOC_PAYLOAD_MAX_SIZE + 2], k3m_or_k3ae_buf[EDHOC_K23M_MAX_SIZE],
            iv3m_or_iv3ae_buf[EDHOC_IV23M_MAX_SIZE], a_3ae[EDHOC_MAX_A3AE_LEN];

    hash_ctx_t hash_ctx;

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (suite_info == NULL)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    aead = suite_info->aead_algo;
    aead_info = cose_aead_info_from_id(aead);

    if (aead_info == NULL)
        return EDHOC_ERR_AEAD_UNAVAILABLE;

    key_len = aead_info->key_length;
    iv_len = aead_info->iv_length;
    tag_len = aead_info->tag_length;

    // decode message 1
    EDHOC_CHECK_SUCCESS(edhoc_msg3_decode(ctx, msg3_buf, msg3_len));

    // compute prk_4x3m
    EDHOC_CHECK_SUCCESS(
            crypt_compute_prk4x3m(ctx->conf->role, ctx->method, ctx->secret, ctx->prk_3e2m, ctx->session.prk_4x3m));

    // Start computation transcript hash 3
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));

    // update transcript with th_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_2,
                                     EDHOC_HASH_MAX_SIZE,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_2
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_2,
                                     ctx->ct_or_pld_2_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    if ((data3_len = edhoc_data3_encode(ctx->correlation,
                                        ctx->session.cidr,
                                        ctx->session.cidr_len,
                                        cbor_enc_buf,
                                        sizeof(cbor_enc_buf))) < EDHOC_SUCCESS) {
        ret = data3_len;
        goto exit;
    }

    // update transcript with data 3
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, data3_len));

    // store th_3 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->th_3));

    if ((a3ae_len = edhoc_a3ae_encode(ctx->th_3, a_3ae, EDHOC_MAX_A3AE_LEN)) < EDHOC_SUCCESS) {
        ret = a3ae_len;
        goto exit;
    }

    // before decryption of ciphertext_3, start computation TH_4
    EDHOC_CHECK_SUCCESS(crypt_hash_init(&hash_ctx));

    // update transcript with th_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->th_3,
                                     EDHOC_HASH_MAX_SIZE,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // update transcript with ciphertext_3
    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ctx->ct_or_pld_3,
                                     ctx->ct_or_pld_3_len,
                                     cbor_enc_buf,
                                     size,
                                     sizeof(cbor_enc_buf)));

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hash_ctx, cbor_enc_buf, size));

    // store th_4 in the EDHOC context
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hash_ctx, ctx->session.th_4));

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "K_3ae", key_len, k3m_or_k3ae_buf));
    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->th_3, "IV_3ae", iv_len, iv3m_or_iv3ae_buf));

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
