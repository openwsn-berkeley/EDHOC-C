#include <string.h>

#include "edhoc/edhoc.h"
#include "edhoc/cipher_suites.h"
#include "cbor/cbor_internal.h"

/*
 * Different elements of message 1
 */
enum {
    METHOD_CORR = 0,
    SUITES,
    G_X,
    C_I,
    AD_1,
};

const int CBOR_ARRAY_INFO_LENGTH = 4;


ssize_t edhoc_info_encode(
        cose_algo_t id,
        const uint8_t *th,
        const char *label,
        size_t len,
        uint8_t *out,
        size_t olen) {

    ssize_t size, written;

    size = 0;

    CBOR_CHECK_RET(cbor_create_array(out, CBOR_ARRAY_INFO_LENGTH, size, olen));
    CBOR_CHECK_RET(cbor_array_append_int(id, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(th, COSE_DIGEST_LEN, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_string(label, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_int(len, out, size, olen));

    exit:
    return size;
}


ssize_t edhoc_msg1_encode(corr_t corr,
                          method_t method,
                          cipher_suite_t suite,
                          cose_key_t *key,
                          const uint8_t *cidi,
                          size_t cidi_len,
                          const uint8_t *ad1,
                          size_t ad1_len,
                          uint8_t *out,
                          size_t olen) {
    ssize_t size, written;
    int8_t single_byte_conn_id;
    uint8_t method_corr;
    uint8_t cipher_list[edhoc_supported_suites_len() + 1];

    size = 0;
    method_corr = method * 4 + corr;

    CBOR_CHECK_RET(cbor_int_encode(method_corr, out, size, olen));

    if (edhoc_supported_suites_len() == 1) {
        CBOR_CHECK_RET(cbor_int_encode(*edhoc_supported_suites(), out, size, olen));
    } else {
        cipher_list[0] = suite;
        for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
            cipher_list[i + 1] = edhoc_supported_suites()[i];
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

    if (ad1_len != 0 && ad1 != NULL) {
        CBOR_CHECK_RET(cbor_bytes_encode(ad1, ad1_len, out, size, olen));
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
static int has_support(cipher_suite_t suite) {
    int ret;

    ret = EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    for (size_t i = 0; i < edhoc_supported_suites_len(); ++i) {
        if (suite == edhoc_supported_suites()[i]) {
            ret = EDHOC_SUCCESS;
            break;
        }
    }

    return ret;
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
static int
verify_cipher_suite(cipher_suite_t preferred_suite, const cipher_suite_t *remote_suites, size_t remote_suites_len) {

    if (has_support(preferred_suite) != EDHOC_SUCCESS)
        return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

    for (size_t i = 0; i < remote_suites_len; i++) {
        if (has_support(remote_suites[i]) && remote_suites[i] != preferred_suite)
            return EDHOC_ERR_ILLEGAL_CIPHERSUITE;
        else if (has_support(remote_suites[i]) && remote_suites[i] == preferred_suite)
            return EDHOC_SUCCESS;
        else
            continue;
    }

    return EDHOC_SUCCESS;
}

int edhoc_msg2_decode(edhoc_ctx_t *ctx, const uint8_t *msg2, size_t msg2_len){
    int ret;


}

int edhoc_msg1_decode(edhoc_ctx_t *ctx, const uint8_t *msg1, size_t msg1_len) {
    int ret;
    int8_t *single_byte_conn_id;
    cn_cbor *cbor[5] = {NULL};
    cn_cbor *final_cbor = NULL;
    uint8_t field = 0;
    uint8_t method_corr;
    uint8_t rSize;
    cn_cbor_errback cbor_err;

    ret = EDHOC_ERR_CBOR_DECODING;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(msg1, msg1_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(msg1, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_DECODE_MESSAGE1;

        msg1 = &msg1[rSize];
        msg1_len = msg1_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    if (cbor[METHOD_CORR]->type == CN_CBOR_UINT) {
        method_corr = cbor[METHOD_CORR]->v.uint;
        ctx->correlation = method_corr % 4;

        if ((ctx->method = (method_t *) edhoc_select_auth_method((method_corr - ctx->correlation) / 4)) == NULL)
            return EDHOC_ERR_ILLEGAL_METHOD;

    } else {
        goto exit;
    }

    if (cbor[SUITES]->type == CN_CBOR_UINT) {
        if ((ret = verify_cipher_suite(
                cbor[SUITES]->v.uint, (cipher_suite_t *) &cbor[SUITES]->v.uint, 1)) != EDHOC_SUCCESS) {
            goto exit;
        } else {
            // if the initiator's preferred cipher suite is not supported, then the resulting value will be NULL
            // this should never happen, because it was already checked by verify_cipher_suite()
            if ((ctx->session.selected_suite = (cipher_suite_t *) edhoc_select_suite(cbor[SUITES]->v.uint)) == NULL)
                return EDHOC_ERR_ILLEGAL_CIPHERSUITE;

        }

    } else if (cbor[SUITES]->type == CN_CBOR_ARRAY) {
        if ((ret = verify_cipher_suite(cbor[SUITES]->v.bytes[0],
                                       (cipher_suite_t *) cbor[SUITES]->v.bytes,
                                       cbor[SUITES]->length)) != EDHOC_SUCCESS) {
            goto exit;
        } else {
            // if the initiator's preferred cipher suite is not supported, then the resulting value will be NULL
            // this should never happen, because it was already checked by verify_cipher_suite()
            if ((ctx->session.selected_suite =
                         (cipher_suite_t *) edhoc_select_suite(cbor[SUITES]->v.bytes[0])) == NULL)
                return EDHOC_ERR_ILLEGAL_CIPHERSUITE;
        }
    } else {
        goto exit;
    }

    if (cbor[G_X]->type == CN_CBOR_BYTES && cbor[G_X]->length != 0) {
        if (cbor[G_X]->length <= COSE_MAX_KEY_LEN) {
            memcpy(&ctx->remote_eph_key.x, (uint8_t *) cbor[G_X]->v.bytes, cbor[G_X]->length);
            ctx->remote_eph_key.x_len = cbor[G_X]->length;
            ctx->remote_eph_key.crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite);
            ctx->remote_eph_key.kty = edhoc_kty_from_suite(*ctx->session.selected_suite);
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }
    } else {
        goto exit;
    }

    if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length != 0) {

        if (cbor[G_X]->length <= EDHOC_MAX_CID_LEN) {
            memcpy(&ctx->session.cidi, (uint8_t *) cbor[C_I]->v.bytes, cbor[G_X]->length);
            ctx->session.cidi_len = cbor[G_X]->length;
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }

    } else if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length == 0) {
        memset(ctx->session.cidi, 0, EDHOC_MAX_CID_LEN);
        ctx->session.cidi_len = 0;
    } else if (cbor[C_I]->type == CN_CBOR_INT) {
        single_byte_conn_id = (int8_t *) &cbor[C_I]->v.sint;
        *single_byte_conn_id = *single_byte_conn_id + 24;
        ctx->session.cidi[0] = *(uint8_t *) single_byte_conn_id;
        ctx->session.cidi_len = 1;
    } else {
        goto exit;
    }

    if (cbor[AD_1] != NULL) {
        if (cbor[AD_1]->type == CN_CBOR_BYTES) {
            //TODO: implement callback for ad1 delivery
        }
    }

    ret = EDHOC_SUCCESS;

    exit:
    return ret;
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

