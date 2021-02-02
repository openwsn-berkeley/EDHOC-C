#include <string.h>

#include "edhoc/edhoc.h"

#include "format.h"
#include "cipher_suites.h"
#include "cbor.h"

#define SUPPORTED_SUITES_BUFFER_SIZE     (8)
#define CBOR_ARRAY_INFO_LEN              (4)


ssize_t edhoc_msg1_encode(corr_t corr,
                          uint8_t method,
                          uint8_t cipher_suite,
                          cose_key_t *key,
                          const uint8_t *cidi,
                          size_t cidi_len,
                          ad_cb_t ad1,
                          uint8_t *out,
                          size_t olen) {
    ssize_t size, written, ad1_len;
    int8_t single_byte_conn_id;
    uint8_t method_corr;
    uint8_t cipher_list[edhoc_supported_suites_len() + 1];
    uint8_t ad1_buf[EDHOC_ADD_DATA_MAX_SIZE];

    size = 0;
    method_corr = method * 4 + corr;

    CBOR_CHECK_RET(cbor_int_encode(method_corr, out, size, olen));

    if (edhoc_supported_suites_len() == 1) {
        CBOR_CHECK_RET(cbor_int_encode(edhoc_supported_suites()[0].id, out, size, olen));
    } else {
        cipher_list[0] = cipher_suite;
        for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
            cipher_list[i + 1] = edhoc_supported_suites()[i].id;
        }
        CBOR_CHECK_RET(cbor_bytes_encode(cipher_list, edhoc_supported_suites_len() + 1, out, size, olen));
    }

    CBOR_CHECK_RET(cbor_bytes_encode(key->x, key->x_len, out, size, olen));

    if (cidi_len == 1) {
        single_byte_conn_id = cidi[0] - 24;
        CBOR_CHECK_RET(cbor_int_encode(single_byte_conn_id, out, size, olen));
    } else {
        CBOR_CHECK_RET(cbor_bytes_encode(cidi, cidi_len, out, size, olen));
    }

    if (ad1 != NULL)
        ad1(ad1_buf, EDHOC_ADD_DATA_MAX_SIZE, &ad1_len);

    if (ad1 != NULL) {
        CBOR_CHECK_RET(cbor_bytes_encode(ad1_buf, ad1_len, out, size, olen));
    }

    exit:
    return size;
}

/**
 * @brief Checks if a cipher suite is supported by the implementation
 *
 * @param suite[in]     EDHOC cipher suite
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_ILLEGAL_CIPHERSUITE
 **/
static int has_support(uint8_t cipher_suite) {
    const cipher_suite_t *supported_suites = NULL;

    supported_suites = edhoc_supported_suites();

    if (cipher_suite > EDHOC_CIPHER_SUITE_3)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    if (supported_suites == NULL)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
        if (cipher_suite == supported_suites[i].id) {
            return EDHOC_SUCCESS;
        }
    }

    return EDHOC_ERR_INVALID_CIPHERSUITE;
}

/**
 * @brief Verifies if the Initiator's preferred cipher suite, is truly the best choice.
 *
 * @param preferred_suite[in]   Selected suite by the Initiator
 * @param remote_suites[in]     Suites supported by the Responder
 * @param remote_suites_len[in] Length of @p remote_suites
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_ILLEGAL_CIPHERSUITE
 **/
static int verify_cipher_suite(uint8_t preferred_suite, const uint8_t *remote_suites, size_t remote_suites_len) {

    if (has_support(preferred_suite) != EDHOC_SUCCESS)
        return EDHOC_ERR_INVALID_CIPHERSUITE;

    for (size_t i = 0; i < remote_suites_len; i++) {
        if (has_support(remote_suites[i]) && remote_suites[i] != preferred_suite)
            return EDHOC_ERR_INVALID_CIPHERSUITE;
        else if (has_support(remote_suites[i]) && remote_suites[i] == preferred_suite)
            return EDHOC_SUCCESS;
        else
            continue;
    }

    return EDHOC_SUCCESS;
}

int edhoc_msg3_decode(edhoc_ctx_t *ctx, const uint8_t *msg3, size_t msg3_len) {
    int ret;
    size_t len;
    ssize_t size, written;
    const uint8_t *pt;
    uint8_t tmp;

    size = 0;
    ret = EDHOC_ERR_CBOR_DECODING;

    if (ctx->correlation == NO_CORR || ctx->correlation == CORR_1_2) {
        pt = &tmp;
        CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &len, msg3, size, msg3_len));
        // TODO: copy connection identifier into temporary buffer and verify that it is known.
    }

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &ctx->ct_or_pld_3_len, msg3, size, msg3_len));
    memcpy(ctx->ct_or_pld_3, pt, ctx->ct_or_pld_3_len);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_msg2_decode(edhoc_ctx_t *ctx, const uint8_t *msg2, size_t msg2_len) {
    int ret;
    size_t len;
    ssize_t size, written;
    const uint8_t *pt;
    uint8_t tmp;
    const cipher_suite_t *suite_info;

    size = 0;
    ret = EDHOC_ERR_CBOR_DECODING;
    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (ctx->correlation == NO_CORR || ctx->correlation == CORR_2_3) {
        pt = &tmp;
        CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &len, msg2, size, msg2_len));
        // TODO: copy connection identifier into temporary buffer and verify that it is known.
    }

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &ctx->remote_eph_key.x_len, msg2, size, msg2_len));
    memcpy(ctx->remote_eph_key.x, pt, ctx->remote_eph_key.x_len);
    ctx->remote_eph_key.crv = suite_info->dh_curve;
    ctx->remote_eph_key.kty = suite_info->key_type;

    pt = &tmp;
    CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &ctx->session.cidr_len, msg2, size, msg2_len));
    memcpy(ctx->session.cidr, pt, ctx->session.cidr_len);

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &ctx->ct_or_pld_2_len, msg2, size, msg2_len));
    memcpy(ctx->ct_or_pld_2, pt, ctx->ct_or_pld_2_len);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_msg1_decode(edhoc_ctx_t *ctx, const uint8_t *msg1, size_t msg1_len) {
    size_t len;
    ssize_t size, written;
    int ret, method_corr, corr;
    const method_t *method_info;
    const cipher_suite_t *suite_info;
    uint8_t tmp;
    const uint8_t *pt;
    // uint8_t ad[EDHOC_MAX_EXAD_DATA_LEN];
    uint8_t suites[SUPPORTED_SUITES_BUFFER_SIZE];

    tmp = 0;
    len = 0;
    method_corr = 0;
    size = 0;

    ret = EDHOC_ERR_CBOR_DECODING;

    CBOR_CHECK_RET(cbor_int_decode(&method_corr, msg1, size, msg1_len));

    corr = method_corr % 4;
    if (corr < NO_CORR || corr >= CORR_UNSET) {
        return EDHOC_ERR_INVALID_CORR;
    } else {
        ctx->correlation = corr;
    }

    method_info = edhoc_auth_method_from_id((method_corr - ctx->correlation) / 4);
    if (method_info == NULL) {
        return EDHOC_ERR_INVALID_AUTH_METHOD;
    } else {
        ctx->method = method_info->id;
    }

    pt = &tmp;
    CBOR_CHECK_RET(cbor_suites_decode((uint8_t **) &pt, &len, msg1, size, msg1_len));

    if (len < SUPPORTED_SUITES_BUFFER_SIZE && len > 0)
        memcpy(suites, pt, len);
    else
        return EDHOC_ERR_BUFFER_OVERFLOW;

    EDHOC_CHECK_SUCCESS(verify_cipher_suite(suites[0], &suites[0], len));
    suite_info = edhoc_cipher_suite_from_id(suites[0]);

    if (suite_info != NULL) {
        ctx->session.cipher_suite = suite_info->id;
    } else {
        return EDHOC_ERR_INVALID_CIPHERSUITE;
    }

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &ctx->remote_eph_key.x_len, msg1, size, msg1_len));
    memcpy(ctx->remote_eph_key.x, pt, ctx->remote_eph_key.x_len);
    ctx->remote_eph_key.crv = suite_info->dh_curve;
    ctx->remote_eph_key.kty = suite_info->key_type;

    pt = &tmp;
    CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &ctx->session.cidi_len, msg1, size, msg1_len));
    memcpy(ctx->session.cidi, pt, ctx->session.cidi_len);

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &len, msg1, size, msg1_len));
    if (len != 0) {
        // TODO: implement callbacks for ad1 delivery
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}


ssize_t edhoc_info_encode(
        cose_algo_t id,
        const uint8_t *th,
        const char *label,
        size_t len,
        uint8_t *out,
        size_t olen) {

    ssize_t size, written;

    size = 0;

    CBOR_CHECK_RET(cbor_create_array(out, CBOR_ARRAY_INFO_LEN, size, olen));
    CBOR_CHECK_RET(cbor_array_append_int(id, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(th, EDHOC_HASH_MAX_SIZE, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_string(label, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_int(len, out, size, olen));

    exit:
    return size;
}



ssize_t edhoc_data3_encode(corr_t corr, const uint8_t *cidr, size_t cidr_len, uint8_t *out, size_t olen) {
    ssize_t size, written;
    int8_t single_byte_cid;

    size = 0;

    if (corr == CORR_2_3 || corr == CORR_ALL) {
        return 0;
    } else {
        if (cidr_len == 1) {
            single_byte_cid = cidr[0] - 24;
            CBOR_CHECK_RET(cbor_int_encode(single_byte_cid, out, size, olen));
        } else if (cidr_len > 1) {
            CBOR_CHECK_RET(cbor_bytes_encode(cidr, cidr_len, out, size, olen));
        }
    }

    exit:
    return size;
}

ssize_t edhoc_data2_encode(corr_t corr,
                           const uint8_t *cidi,
                           size_t cidi_len,
                           const uint8_t *cidr,
                           size_t cidr_len,
                           const cose_key_t *eph_key,
                           uint8_t *out,
                           size_t olen) {

    ssize_t size, written;
    int8_t single_byte_cid;

    size = 0;
    memset(out, 0, olen);

    if (corr == NO_CORR || corr == CORR_2_3) {
        if (cidi_len == 1) {
            single_byte_cid = cidi[0] - 24;
            CBOR_CHECK_RET(cbor_int_encode(single_byte_cid, out, size, olen));
        } else if (cidi_len > 1) {
            CBOR_CHECK_RET(cbor_bytes_encode(cidi, cidi_len, out, size, olen));
        }
    }

    CBOR_CHECK_RET(cbor_bytes_encode(eph_key->x, eph_key->x_len, out, size, olen));

    // even if length of responder conn id is zero we need to add it.
    if (cidr_len == 1) {
        single_byte_cid = cidr[0] - 24;
        CBOR_CHECK_RET(cbor_int_encode(single_byte_cid, out, size, olen));
    } else {
        CBOR_CHECK_RET(cbor_bytes_encode(cidi, cidi_len, out, size, olen));
    }

    exit:
    return size;
}

ssize_t edhoc_cose_external_aad_encode(const uint8_t *th,
                                       const uint8_t *cred,
                                       size_t cred_len,
                                       ad_cb_t ad2,
                                       uint8_t *out,
                                       size_t olen) {

    ssize_t size, written, ad2_len;
    uint8_t ad2_buf[EDHOC_ADD_DATA_MAX_SIZE];

    size = 0;

    if (ad2 != NULL)
        ad2(ad2_buf, EDHOC_ADD_DATA_MAX_SIZE, &ad2_len);

    CBOR_CHECK_RET(cbor_bytes_encode(th, EDHOC_HASH_MAX_SIZE, out, size, olen));
    CBOR_CHECK_RET(cbor_bytes_encode(cred, cred_len, out, size, olen));

    if (ad2 != NULL) {
        CBOR_CHECK_RET(cbor_bytes_encode(ad2_buf, ad2_len, out, size, olen));
    }

    exit:
    return size;
}

ssize_t edhoc_cose_enc_struct_encode(const uint8_t *cred_id,
                                     size_t cred_id_len,
                                     const uint8_t *external_aad,
                                     size_t external_aad_len,
                                     uint8_t *out,
                                     size_t olen) {
    ssize_t ret;
    ssize_t size, written;

    ret = EDHOC_ERR_CBOR_ENCODING;
    size = 0;

    CBOR_CHECK_RET(cbor_create_array(out, 3, 0, olen));
    CBOR_CHECK_RET(cbor_array_append_string("Encrypt0", out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(cred_id, cred_id_len, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(external_aad, external_aad_len, out, size, olen));

    ret = size;
    exit:
    return ret;
}

ssize_t edhoc_msg2_encode(const uint8_t *data2,
                          size_t data2_len,
                          const uint8_t *ct2,
                          size_t ct2_len,
                          uint8_t *out,
                          size_t olen) {
    ssize_t size, written;

    // data_2 is already a CBOR sequence
    memcpy(out, data2, data2_len);

    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ct2, ct2_len, out + data2_len, size, olen));

    exit:
    return size + data2_len;
}

ssize_t edhoc_msg3_encode(const uint8_t *data3,
                          size_t data3_len,
                          const uint8_t *ct3,
                          size_t ct3_len,
                          uint8_t *out,
                          size_t olen) {
    ssize_t size, written;

    // data_2 is already a CBOR sequence
    memcpy(out, data3, data3_len);

    size = 0;
    CBOR_CHECK_RET(cbor_bytes_encode(ct3, ct3_len, out + data3_len, size, olen));

    exit:
    return size + data3_len;
}

ssize_t edhoc_p2e_or_p3ae_encode(edhoc_ctx_t *ctx, uint8_t *signature_23, uint8_t *out, size_t olen) {
    ssize_t size, written;

    size = 0;

    if (ctx->conf->cred_id_len > olen)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    // copy the CBOR encoding from CRED_ID to the output buffer
    memcpy(out, ctx->conf->cred_id, ctx->conf->cred_id_len);
    size += ctx->conf->cred_id_len;

    // append CBOR encoding of signature_2
    CBOR_CHECK_RET(cbor_bytes_encode(signature_23, EDHOC_SIG23_MAX_SIZE, out, size, olen));

    exit:
    return size;
}

ssize_t edhoc_a3ae_encode(const uint8_t *th3, uint8_t *out, size_t olen) {
    ssize_t ret;
    ssize_t size, written;

    size = 0;
    ret = EDHOC_ERR_CBOR_ENCODING;

    CBOR_CHECK_RET(cbor_create_array(out, 3, size, olen));
    CBOR_CHECK_RET(cbor_array_append_string("Encrypt0", out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(NULL, 0, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(th3, EDHOC_HASH_MAX_SIZE, out, size, olen));

    ret = size;
    exit:
    return ret;
}

int edhoc_p3ae_decode(uint8_t *p3ae, size_t p3ae_len) {
    (void) p3ae;
    (void) p3ae_len;

    // TODO: verify signature
    return EDHOC_SUCCESS;
}

int edhoc_p2e_decode(uint8_t *p2e, size_t p2e_len) {
    (void) p2e;
    (void) p2e_len;

    // TODO: verify signature
    return EDHOC_SUCCESS;
}
