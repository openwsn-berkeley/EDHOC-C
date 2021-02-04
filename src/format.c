#include <string.h>

#include "edhoc/edhoc.h"

#include "format.h"
#include "cipher_suites.h"
#include "cbor.h"
#include "credentials.h"

#define SUPPORTED_SUITES_BUFFER_SIZE     (8)
#define CBOR_ARRAY_INFO_LEN              (4)


ssize_t edhoc_msg1_encode(corr_t corr,
                          method_t m,
                          cipher_suite_id_t id,
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
    method_corr = m * 4 + corr;

    CBOR_CHECK_RET(cbor_int_encode(method_corr, out, size, olen));

    if (edhoc_supported_suites_len() == 1) {
        CBOR_CHECK_RET(cbor_int_encode(edhoc_supported_suites()[0].id, out, size, olen));
    } else {
        cipher_list[0] = id;
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
        return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;

    if (supported_suites == NULL)
        return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;

    for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
        if (cipher_suite == supported_suites[i].id) {
            return EDHOC_SUCCESS;
        }
    }

    return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;
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
        return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;

    for (size_t i = 0; i < remote_suites_len; i++) {
        if (has_support(remote_suites[i]) && remote_suites[i] != preferred_suite)
            return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;
        else if (has_support(remote_suites[i]) && remote_suites[i] == preferred_suite)
            return EDHOC_SUCCESS;
        else
            continue;
    }

    return EDHOC_SUCCESS;
}

int edhoc_msg3_decode(edhoc_msg3_t *msg3, corr_t correlation, const uint8_t *msg3_buf, size_t msg3_len) {
    int ret;
    ssize_t size, written;
    uint8_t *pt, tmp;

    size = 0;
    ret = EDHOC_ERR_CBOR_DECODING;

    if (correlation == NO_CORR || correlation == CORR_1_2) {
        pt = &tmp;
        CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &msg3->cidr_len, msg3_buf, size, msg3_len));
        msg3->cidr = pt;
    }

    CBOR_CHECK_RET(cbor_bytes_decode(&msg3->ciphertext3, &msg3->ciphertext3_len, msg3_buf, size, msg3_len));

    msg3->data3 = msg3_buf;
    msg3->data3_len = msg3->cidr_len;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_msg2_decode(edhoc_msg2_t *msg2, corr_t corr, const uint8_t *msg2_buf, size_t msg2_len) {
    int ret;
    ssize_t size, written;
    uint8_t *pt, tmp;

    size = 0;
    ret = EDHOC_ERR_CBOR_DECODING;

    if (corr == NO_CORR || corr == CORR_2_3) {
        pt = &tmp;
        CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &msg2->cidi_len, msg2_buf, size, msg2_len));
        msg2->cidi = pt;
    }

    CBOR_CHECK_RET(cbor_bytes_decode(&msg2->g_y, &msg2->g_y_len, msg2_buf, size, msg2_len));

    pt = &tmp;
    CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &msg2->cidr_len, msg2_buf, size, msg2_len));
    msg2->cidr = pt;

    msg2->data2 = msg2_buf;
    msg2->data2_len = size;

    CBOR_CHECK_RET(cbor_bytes_decode((const uint8_t **) &msg2->ciphertext2,
                                     &msg2->ciphertext2_len,
                                     msg2_buf,
                                     size,
                                     msg2_len));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_msg1_decode(edhoc_msg1_t *msg1, const uint8_t *msg1_buf, size_t msg1_len) {
    size_t len;
    ssize_t size, written;
    int ret;
    const cipher_suite_t *suite_info;
    uint8_t tmp;
    const uint8_t *pt;
    uint8_t suites[SUPPORTED_SUITES_BUFFER_SIZE];

    tmp = 0;
    len = 0;
    size = 0;

    ret = EDHOC_ERR_CBOR_DECODING;

    CBOR_CHECK_RET(cbor_int_decode((int *) &msg1->method_corr, msg1_buf, size, msg1_len));

    pt = &tmp;
    CBOR_CHECK_RET(cbor_suites_decode((uint8_t **) &pt, &len, msg1_buf, size, msg1_len));

    if (len < SUPPORTED_SUITES_BUFFER_SIZE && len > 0)
        memcpy(suites, pt, len);
    else
        return EDHOC_ERR_BUFFER_OVERFLOW;

    EDHOC_CHECK_SUCCESS(verify_cipher_suite(suites[0], &suites[0], len));

    if ((suite_info = edhoc_cipher_suite_from_id(suites[0])) == NULL)
        return EDHOC_ERR_CIPHERSUITE_UNAVAILABLE;
    else
        msg1->cipher_suite = suite_info->id;

    CBOR_CHECK_RET(cbor_bytes_decode(&msg1->g_x, &msg1->g_x_len, msg1_buf, size, msg1_len));

    pt = &tmp;
    CBOR_CHECK_RET(cbor_bstr_id_decode((uint8_t **) &pt, &msg1->cidi_len, msg1_buf, size, msg1_len));
    msg1->cidi = pt;

    CBOR_CHECK_RET(cbor_bytes_decode(&msg1->ad1, &msg1->ad1_len, msg1_buf, size, msg1_len));

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

ssize_t edhoc_cose_ex_aad_encode(const uint8_t *th,
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

    // cred is already CBOR encoded
    if (size + cred_len <= olen) {
        memcpy(out + size, cred, cred_len);
        size += cred_len;
    } else {
        return EDHOC_ERR_BUFFER_OVERFLOW;
    }

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

ssize_t edhoc_a23m_encode(const uint8_t *auth_bytes,
                          size_t auth_len,
                          const uint8_t *cred_id,
                          size_t cred_id_len,
                          const uint8_t *th23,
                          uint8_t *out,
                          size_t olen) {
    ssize_t ret;
    ssize_t eaad_len;
    ssize_t enc_len;

    const uint8_t *start_eaad;

    if ((eaad_len = edhoc_cose_ex_aad_encode(th23, auth_bytes, auth_len, NULL, out, olen)) <= 0) {
        if (eaad_len < 0) {
            EDHOC_FAIL(eaad_len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_MSG_SIZE);
        }
    }

    // move to the back of the buffer
    memcpy(out + olen - eaad_len, out, eaad_len);

    start_eaad = out + olen - eaad_len;
    if ((enc_len = edhoc_cose_enc_struct_encode(cred_id, cred_id_len, start_eaad, eaad_len, out, olen)) <= 0) {
        if (enc_len < 0) {
            EDHOC_FAIL(enc_len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_MSG_SIZE);
        }
    }

    ret = enc_len;
    exit:
    return ret;
}

ssize_t edhoc_m23_encode(const uint8_t *th23,
                         const uint8_t *auth_bytes,
                         size_t auth_len,
                         const uint8_t *cred_id,
                         size_t cred_id_len,
                         ad_cb_t ad23,
                         const uint8_t *tag,
                         size_t tag_len,
                         uint8_t *out,
                         size_t olen) {

    ssize_t eaad_len, size, written;
    ssize_t ret;

    size = 0;

    if ((eaad_len = edhoc_cose_ex_aad_encode(th23, auth_bytes, auth_len, ad23, out, olen)) <= 0) {
        if (eaad_len < 0) {
            EDHOC_FAIL(eaad_len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_MSG_SIZE);
        }
    }

    // move to the back of the buffer
    memcpy(out + olen - eaad_len, out, eaad_len);

    ret = EDHOC_ERR_CBOR_ENCODING;
    CBOR_CHECK_RET(cbor_create_array(out, 4, size, olen));
    CBOR_CHECK_RET(cbor_array_append_string("Signature1", out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(cred_id, cred_id_len, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(out + olen - eaad_len, eaad_len, out, size, olen));
    CBOR_CHECK_RET(cbor_array_append_bytes(tag, tag_len, out, size, olen));

    ret = size;
    exit:
    return ret;
}

ssize_t edhoc_p2e_or_p3ae_encode(uint8_t *cred_id,
                                 size_t cred_id_len,
                                 uint8_t *sig_or_mac23,
                                 size_t sig_or_mac23_len,
                                 uint8_t *out,
                                 size_t olen) {
    ssize_t size, written;

    size = 0;

    if (olen < cred_id_len)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    // copy the CBOR encoded CRED_ID to the output buffer
    memcpy(out, cred_id, cred_id_len);
    size += cred_id_len;

    // append CBOR encoding of signature_2
    CBOR_CHECK_RET(cbor_bytes_encode(sig_or_mac23, sig_or_mac23_len, out, size, olen));

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

int edhoc_p3ae_decode(edhoc_ctx_t *ctx, uint8_t *p3ae, size_t p3ae_len) {
    (void) ctx;
    (void) p3ae;
    (void) p3ae_len;

    // TODO: verify signature
    return EDHOC_SUCCESS;
}

int edhoc_p2e_decode(edhoc_msg2_t *msg2, const uint8_t *p2e, size_t p2e_len) {

    // TODO: verify signature
    return EDHOC_SUCCESS;
}
