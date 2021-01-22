#include <string.h>

#include "edhoc/edhoc.h"
#include "edhoc/cipher_suites.h"
#include "cbor/cbor_internal.h"

/*
 * Different elements of message 1
 */
enum msg1_fields {
    M1_METHOD_CORR = 0,
    M1_SUITES,
    M1_G_X,
    M1_C_I,
    M1_AD_1,
    M1_FINAL
};

enum msg2_fields {
    M2_C_I = 0,
    M2_G_Y,
    M2_C_R,
    M2_CIPHERTEXT,
    M2_FINAL
};

enum msg3_fields {
    M3_C_R = 0,
    M3_CIPHERTEXT,
    M3_FINAL
};

enum p2e_fields {
    P2E_ID_CRED = 0,
    P2E_SIG_OR_MAC,
    P2E_AD,
    P2E_FINAL
};

enum p3ae_fields {
    P3AE_ID_CRED = 0,
    P3AE_SIG_OR_MAC,
    P3AE_FINAL
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
                          ad_cb_t ad1,
                          uint8_t *out,
                          size_t olen) {
    ssize_t size, written, ad1_len;
    int8_t single_byte_conn_id;
    uint8_t method_corr;
    uint8_t cipher_list[edhoc_supported_suites_len() + 1];
    uint8_t ad1_buf[EDHOC_MAX_EXAD_DATA_LEN];

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

    if (ad1 != NULL)
        ad1(ad1_buf, EDHOC_MAX_EXAD_DATA_LEN, &ad1_len);

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
static int has_support(cipher_suite_t suite) {
    int ret;

    ret = EDHOC_ERR_INVALID_CIPHERSUITE;

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
    uint8_t field;
    uint8_t rSize;
    cn_cbor *cbor[M3_FINAL] = {NULL};
    cn_cbor *final_cbor = NULL;
    cn_cbor_errback cbor_err;

    field = 0;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(msg3, msg3_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(msg3, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_CBOR_DECODING;

        msg3 = &msg3[rSize];
        msg3_len = msg3_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    // if true, this means there was no C_R in data_3
    if (field != M3_FINAL - 1) {
        cbor[M3_CIPHERTEXT] = cbor[M3_C_R];
        cbor[M3_C_R] = NULL;
    }

    if(cbor[M3_C_R] != NULL){
        if (cbor[M3_C_R]->type == CN_CBOR_BYTES && cbor[M3_C_R]->length != 0) {

            if (cbor[M3_C_R]->length <= EDHOC_MAX_CID_LEN) {
                // TODO: C_R was already set by the responder, so now we have to fetch the context ...
            } else {
                return EDHOC_ERR_BUFFER_OVERFLOW;
            }

        } else if (cbor[M3_C_R]->type == CN_CBOR_BYTES && cbor[M3_C_R]->length == 0) {
            // TODO: C_R was already set by the responder, so now we have to fetch the context ...
        } else if (cbor[M3_C_R]->type == CN_CBOR_INT || cbor[M3_C_R]->type == CN_CBOR_UINT) {
            // TODO: C_R was already set by the responder, so now we have to fetch the context ...
        } else {
            return EDHOC_ERR_CBOR_DECODING;
        }
    }

    if (cbor[M3_CIPHERTEXT]->type == CN_CBOR_BYTES && cbor[M3_CIPHERTEXT]->length > 0) {
        if (cbor[M3_CIPHERTEXT]->length <= EDHOC_MAX_PAYLOAD_LEN) {
            memcpy(ctx->ct_or_pld_3, cbor[M3_CIPHERTEXT]->v.bytes, cbor[M3_CIPHERTEXT]->length);
            ctx->ct_or_pld_3_len = cbor[M3_CIPHERTEXT]->length;
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    return EDHOC_SUCCESS;
}

int edhoc_msg2_decode(edhoc_ctx_t *ctx, const uint8_t *msg2, size_t msg2_len) {
    uint8_t field;
    uint8_t rSize;
    int8_t *single_byte_conn_id;
    cn_cbor *cbor[M2_FINAL] = {NULL};
    cn_cbor *final_cbor = NULL;
    cn_cbor_errback cbor_err;

    field = 0;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(msg2, msg2_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(msg2, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_CBOR_DECODING;

        msg2 = &msg2[rSize];
        msg2_len = msg2_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    // if true, this means there was no C_I in data_2
    if (field != M2_FINAL - 1) {
        cbor[M2_CIPHERTEXT] = cbor[M2_C_R];
        cbor[M2_C_R] = cbor[M2_G_Y];
        cbor[M2_G_Y] = cbor[M2_C_I];
        cbor[M2_C_I] = NULL;
    }

    // check if C_I is included in data_2
    if (cbor[M2_C_I] != NULL) {
        if (cbor[M2_C_I]->type == CN_CBOR_BYTES && cbor[M2_C_I]->length != 0) {

            if (cbor[M2_C_I]->length <= EDHOC_MAX_CID_LEN) {
                memcpy(&ctx->session.cidi, (uint8_t *) cbor[M2_C_I]->v.bytes, cbor[M2_C_I]->length);
                ctx->session.cidi_len = cbor[M2_C_I]->length;
            } else {
                return EDHOC_ERR_BUFFER_OVERFLOW;
            }

        } else if (cbor[M2_C_I]->type == CN_CBOR_BYTES && cbor[M2_C_I]->length == 0) {
            memset(ctx->session.cidi, 0, EDHOC_MAX_CID_LEN);
            ctx->session.cidi_len = 0;
        } else if (cbor[M2_C_I]->type == CN_CBOR_INT) {
            single_byte_conn_id = (int8_t *) &cbor[M1_C_I]->v.sint;
            *single_byte_conn_id = *single_byte_conn_id + 24;
            ctx->session.cidi[0] = *(uint8_t *) single_byte_conn_id;
            ctx->session.cidi_len = 1;
        } else {
            return EDHOC_ERR_CBOR_DECODING;
        }
    }

    if (cbor[M2_G_Y]->type == CN_CBOR_BYTES && cbor[M2_G_Y]->length != 0) {
        if (cbor[M2_G_Y]->length <= COSE_MAX_KEY_LEN) {
            memcpy(&ctx->remote_eph_key.x, (uint8_t *) cbor[M2_G_Y]->v.bytes, cbor[M2_G_Y]->length);
            ctx->remote_eph_key.x_len = cbor[M2_G_Y]->length;
            ctx->remote_eph_key.crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite);
            ctx->remote_eph_key.kty = edhoc_kty_from_suite(*ctx->session.selected_suite);
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M2_C_R]->type == CN_CBOR_BYTES && cbor[M2_C_R]->length != 0) {

        if (cbor[M2_C_R]->length <= EDHOC_MAX_CID_LEN) {
            memcpy(&ctx->session.cidr, (uint8_t *) cbor[M2_C_R]->v.bytes, cbor[M2_C_R]->length);
            ctx->session.cidr_len = cbor[M2_C_R]->length;
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }

    } else if (cbor[M2_C_R]->type == CN_CBOR_BYTES && cbor[M2_C_R]->length == 0) {
        memset(ctx->session.cidr, 0, EDHOC_MAX_CID_LEN);
        ctx->session.cidr_len = 0;
    } else if (cbor[M2_C_R]->type == CN_CBOR_INT || cbor[M2_C_R]->type == CN_CBOR_UINT) {
        single_byte_conn_id = (int8_t *) &cbor[M2_C_R]->v.sint;
        *single_byte_conn_id = *single_byte_conn_id + 24;
        ctx->session.cidr[0] = *(uint8_t *) single_byte_conn_id;
        ctx->session.cidr_len = 1;
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M2_CIPHERTEXT]->type == CN_CBOR_BYTES && cbor[M2_CIPHERTEXT]->length > 0) {
        if (cbor[M2_CIPHERTEXT]->length <= EDHOC_MAX_PAYLOAD_LEN) {
            memcpy(ctx->ct_or_pld_2, cbor[M2_CIPHERTEXT]->v.bytes, cbor[M2_CIPHERTEXT]->length);
            ctx->ct_or_pld_2_len = cbor[M2_CIPHERTEXT]->length;
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    return EDHOC_SUCCESS;
}

int edhoc_msg1_decode(edhoc_ctx_t *ctx, const uint8_t *msg1, size_t msg1_len) {
    int ret;
    int8_t *single_byte_conn_id;
    cn_cbor *cbor[M1_FINAL] = {NULL};
    cn_cbor *final_cbor = NULL;
    uint8_t field;
    uint8_t method_corr;
    uint8_t rSize;
    cn_cbor_errback cbor_err;

    field = 0;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(msg1, msg1_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(msg1, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_CBOR_DECODING;

        msg1 = &msg1[rSize];
        msg1_len = msg1_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    if (cbor[M1_METHOD_CORR]->type == CN_CBOR_UINT) {
        method_corr = cbor[M1_METHOD_CORR]->v.uint;
        ctx->correlation = method_corr % 4;

        if ((ctx->method = (method_t *) edhoc_select_auth_method((method_corr - ctx->correlation) / 4)) == NULL)
            return EDHOC_ERR_INVALID_AUTH_METHOD;

    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M1_SUITES]->type == CN_CBOR_UINT) {

        if ((ret = verify_cipher_suite(
                cbor[M1_SUITES]->v.uint, (cipher_suite_t *) &cbor[M1_SUITES]->v.uint, 1)) != EDHOC_SUCCESS) {
            return EDHOC_ERR_CBOR_DECODING;
        } else {
            // if the initiator's preferred cipher suite is not supported, then the resulting value will be NULL
            // this should never happen, because it was already checked by verify_cipher_suite()
            if ((ctx->session.selected_suite = (cipher_suite_t *) edhoc_select_suite(cbor[M1_SUITES]->v.uint)) == NULL)
                return EDHOC_ERR_INVALID_CIPHERSUITE;

        }

    } else if (cbor[M1_SUITES]->type == CN_CBOR_ARRAY) {
        if ((ret = verify_cipher_suite(cbor[M1_SUITES]->v.bytes[0],
                                       (cipher_suite_t *) cbor[M1_SUITES]->v.bytes,
                                       cbor[M1_SUITES]->length)) != EDHOC_SUCCESS) {
            return ret;
        } else {
            // if the initiator's preferred cipher suite is not supported, then the resulting value will be NULL
            // this should never happen, because it was already checked by verify_cipher_suite()
            if ((ctx->session.selected_suite =
                         (cipher_suite_t *) edhoc_select_suite(cbor[M1_SUITES]->v.bytes[0])) == NULL) {
                return EDHOC_ERR_INVALID_CIPHERSUITE;
            }
        }
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M1_G_X]->type == CN_CBOR_BYTES && cbor[M1_G_X]->length != 0) {
        if (cbor[M1_G_X]->length <= COSE_MAX_KEY_LEN) {
            memcpy(&ctx->remote_eph_key.x, (uint8_t *) cbor[M1_G_X]->v.bytes, cbor[M1_G_X]->length);
            ctx->remote_eph_key.x_len = cbor[M1_G_X]->length;
            ctx->remote_eph_key.crv = edhoc_dh_curve_from_suite(*ctx->session.selected_suite);
            ctx->remote_eph_key.kty = edhoc_kty_from_suite(*ctx->session.selected_suite);
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M1_C_I]->type == CN_CBOR_BYTES && cbor[M1_C_I]->length != 0) {
        if (cbor[M1_C_I]->length <= EDHOC_MAX_CID_LEN) {
            memcpy(&ctx->session.cidi, (uint8_t *) cbor[M1_C_I]->v.bytes, cbor[M1_C_I]->length);
            ctx->session.cidi_len = cbor[M1_C_I]->length;
        } else {
            return EDHOC_ERR_BUFFER_OVERFLOW;
        }

    } else if (cbor[M1_C_I]->type == CN_CBOR_BYTES && cbor[M1_C_I]->length == 0) {
        memset(ctx->session.cidi, 0, EDHOC_MAX_CID_LEN);
        ctx->session.cidi_len = 0;
    } else if (cbor[M1_C_I]->type == CN_CBOR_INT || cbor[M1_C_I]->type == CN_CBOR_UINT) {
        single_byte_conn_id = (int8_t *) &cbor[M1_C_I]->v.sint;
        *single_byte_conn_id = *single_byte_conn_id + 24;
        ctx->session.cidi[0] = *(uint8_t *) single_byte_conn_id;
        ctx->session.cidi_len = 1;
    } else {
        return EDHOC_ERR_CBOR_DECODING;
    }

    if (cbor[M1_AD_1] != NULL) {
        if (cbor[M1_AD_1]->type == CN_CBOR_BYTES) {
            //TODO: implement callback for ad1 delivery
        }
    }

    return EDHOC_SUCCESS;
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

ssize_t cose_ext_aad_encode(const uint8_t *th,
                            const uint8_t *cred,
                            size_t cred_len,
                            ad_cb_t ad2,
                            uint8_t *out,
                            size_t olen) {

    ssize_t size, written, ad2_len;
    uint8_t ad2_buf[EDHOC_MAX_EXAD_DATA_LEN];

    size = 0;

    if (ad2 != NULL)
        ad2(ad2_buf, EDHOC_MAX_EXAD_DATA_LEN, &ad2_len);

    CBOR_CHECK_RET(cbor_bytes_encode(th, COSE_DIGEST_LEN, out, size, olen));
    CBOR_CHECK_RET(cbor_bytes_encode(cred, cred_len, out, size, olen));

    if (ad2 != NULL) {
        CBOR_CHECK_RET(cbor_bytes_encode(ad2_buf, ad2_len, out, size, olen));
    }

    exit:
    return size;
}

ssize_t cose_enc_structure_encode(const uint8_t *cred_id,
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

int edhoc_p3ae_decode(uint8_t *p3ae, size_t p3ae_len){
    cn_cbor *final_cbor;
    size_t rSize, field;
    cn_cbor_errback cbor_err;
    cn_cbor *cbor[P3AE_FINAL] = {NULL};

    field = 0;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(p3ae, p3ae_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(p3ae, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_CBOR_DECODING;

        p3ae = &p3ae[rSize];
        p3ae_len = p3ae_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    // TODO: verify signature
    return EDHOC_SUCCESS;
}

int edhoc_p2e_decode(uint8_t *p2e, size_t p2e_len) {
    cn_cbor *final_cbor;
    size_t rSize, field;
    cn_cbor_errback cbor_err;
    cn_cbor *cbor[P2E_FINAL] = {NULL};

    field = 0;

    // iterate over the CBOR sequence until all elements are decoded
    while ((final_cbor = cn_cbor_decode(p2e, p2e_len, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(p2e, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            return EDHOC_ERR_CBOR_DECODING;

        p2e = &p2e[rSize];
        p2e_len = p2e_len - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    // TODO: verify signature
    return EDHOC_SUCCESS;
}
