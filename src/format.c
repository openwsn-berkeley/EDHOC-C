#include <string.h>

#include "format.h"
#include "ciphersuites.h"
#include "cbor.h"

#if defined(EDHOC_AUTH_X509_CERT)
#if defined(MBEDTLS)

#include <mbedtls/x509_crt.h>

#else
#error "No X509 backend enabled"
#endif
#endif

#if defined(NANOCBOR)

#include <nanocbor/nanocbor.h>

#else
#error "No CBOR backend enabled"
#endif


#define CBOR_ARRAY_INFO_LEN              (4)

void format_msg1_init(edhoc_msg1_t *msg1) {
    memset(msg1, 0, sizeof(edhoc_msg1_t));
}

void format_msg2_init(edhoc_msg2_t *msg2) {
    memset(msg2, 0, sizeof(edhoc_msg2_t));
}

void format_msg3_init(edhoc_msg3_t *msg3) {
    memset(msg3, 0, sizeof(edhoc_msg3_t));
}

void format_error_msg_init(edhoc_error_msg_t *errMsg) {
    memset(errMsg, 0, sizeof(edhoc_error_msg_t));
}

void format_plaintext23_init(edhoc_plaintext23_t *plaintext) {
    memset(plaintext, 0, sizeof(edhoc_plaintext23_t));
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
 * @param preferredSuite[in]   Selected suite by the Initiator
 * @param alternatives[in]     Suites supported by the Responder
 * @param alternativesLen[in] Length of @p remote_suites
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_ILLEGAL_CIPHERSUITE
 **/
static int verify_cipher_suite(uint8_t preferredSuite, const uint8_t *alternatives, size_t alternativesLen) {
    int ret;

    // first check if the responder supports the preferred suite
    EDHOC_CHECK_SUCCESS(has_support(preferredSuite));

    // verify that no prior cipher suite in the alternatives is supported
    for (size_t i = 0; i < alternativesLen; i++) {
        if (has_support(alternatives[i]) && alternatives[i] != preferredSuite) {
            // if another prior cipher suite is supported, return error
            EDHOC_FAIL(EDHOC_ERR_PRIOR_CIPHERSUITE_SUPPORTED);
        } else if (has_support(alternatives[i]) && alternatives[i] == preferredSuite) {
            // if preferredSuite is the first one that the Responder supports we are good
            break;
        } else {
            // prior alternative not supported by the responder, verify next one
            continue;
        }
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t format_msg1_encode(const edhoc_msg1_t *msg1, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&encoder, out, olen);

    // (1) encode the method_corr
    CBOR_ENC_CHECK_RET(cbor_put_int(&encoder, msg1->methodCorr));

    // (2) encode the EDHOC cipher suite list
    if (edhoc_supported_suites_len() == 1) {
        if (msg1->cipherSuite->id == edhoc_supported_suites()[0].id) {
            CBOR_ENC_CHECK_RET(cbor_put_int(&encoder, edhoc_supported_suites()[0].id));
        } else {
            EDHOC_FAIL(EDHOC_ERR_CBOR_ENCODING);
        }
    } else if (edhoc_supported_suites_len() > 1) {
        EDHOC_CHECK_SUCCESS(has_support(msg1->cipherSuite->id));
        CBOR_ENC_CHECK_RET(cbor_put_array(&encoder, edhoc_supported_suites_len() + 1))
        CBOR_ENC_CHECK_RET(cbor_put_uint(&encoder, msg1->cipherSuite->id));
        for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
            CBOR_ENC_CHECK_RET(cbor_put_uint(&encoder, edhoc_supported_suites()[i].id));
        }
    } else {
        EDHOC_FAIL(EDHOC_ERR_CIPHERSUITE_UNAVAILABLE);
    }

    // (3) encode the public ephemeral key G_X
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, msg1->gX.x, msg1->gX.xLen));

    // (4) encode the Initiator's connection identifier
    if (msg1->cidi.length == 1 && msg1->cidi.integer >= 0 && msg1->cidi.integer <= 0x2f) {
        cbor_put_int(&encoder, (int8_t) (msg1->cidi.integer - 24));
    } else {
        cbor_put_bstr(&encoder, msg1->cidi.bstr, msg1->cidi.length);
    }

    // (5) encode the additional data
    if (msg1->ad1 != NULL && msg1->ad1Len != 0) {
        CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, msg1->ad1, msg1->ad1Len));
    }

    ret = (ssize_t) (cbor_encoded_len(&encoder));
    exit:
    return ret;
}

int format_msg1_decode(edhoc_msg1_t *msg1, const uint8_t *in, size_t ilen) {
    int ret;
    uint8_t suite;

    size_t i;
    uint8_t receivedSuites[10];

    const uint8_t *p;

#if defined(NANOCBOR)
    nanocbor_encoder_t decoder;
    nanocbor_encoder_t arr;
#else
#error "No CBOR backend enabled"
#endif

    // set up the decoder context
    cbor_init_decoder(&decoder, in, ilen);

    // (1) decode the method correlation
    CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&decoder, &msg1->methodCorr));

    // (2) decode the selected cipher suite
    if (cbor_get_type(&decoder) == CBOR_ARRAY) {
        CBOR_DEC_CHECK_RET(cbor_start_decoding_array(&decoder, &arr));

        i = 0;
        while (!cbor_at_end(&arr) && i < sizeof(receivedSuites)) {
            CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&arr, &receivedSuites[i]));
            i++;
        }
        if (i == sizeof(receivedSuites)) {
            EDHOC_FAIL(EDHOC_ERR_BUFFER_OVERFLOW);
        } else {
            EDHOC_CHECK_SUCCESS(verify_cipher_suite(receivedSuites[0], &receivedSuites[1], i - 1));
        }
    } else if (cbor_get_type(&decoder) == CBOR_UINT) {
        cbor_get_uint8_t(&decoder, &suite);
        msg1->cipherSuite = edhoc_cipher_suite_from_id(suite);
        // only option, just verify the support for this cipher suite
        EDHOC_CHECK_SUCCESS(has_support(suite));
    } else {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    if (msg1->cipherSuite == NULL) {
        EDHOC_FAIL(EDHOC_ERR_CIPHERSUITE_UNAVAILABLE);
    }

    // (3) decode the ephemeral key
    if (msg1->cipherSuite->id == EDHOC_CIPHER_SUITE_0 || msg1->cipherSuite->id == EDHOC_CIPHER_SUITE_1) {
        msg1->gX.kty = COSE_KTY_OCTET;
        msg1->gX.crv = COSE_EC_CURVE_X25519;
    } else {
        msg1->gX.kty = COSE_KTY_EC2;
        msg1->gX.crv = COSE_EC_CURVE_P256;
    }

    CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &p, &msg1->gX.xLen));
    memcpy(msg1->gX.x, p, msg1->gX.xLen);

    // TODO: check if valid key?

    // (4) decode connection identifier
    if (cbor_get_type(&decoder) == CBOR_BSTR) {
        CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg1->cidi.bstr, &msg1->cidi.length));
    } else if (cbor_get_type(&decoder) == CBOR_NINT) {
        CBOR_DEC_CHECK_RET(cbor_get_int8_t(&decoder, &msg1->cidi.integer));
        msg1->cidi.integer += 24;
        msg1->cidi.length = 1;
    } else if (cbor_get_type(&decoder) == CBOR_UINT) {
        CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&decoder, (uint8_t *) &(msg1->cidi.integer)));
        msg1->cidi.integer += 24;
        msg1->cidi.length = 1;
    } else {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    if (!cbor_at_end(&decoder)) {
        CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg1->ad1, &msg1->ad1Len));
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t format_msg2_encode(const edhoc_msg2_t *msg2, corr_t corr, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    if ((ret = format_data2_encode(&msg2->data2, corr, out, olen)) < 0) {
        EDHOC_FAIL(ret);
    }

    cbor_init_encoder(&encoder, out + ret, olen - ret);

    CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, msg2->ciphertext2, msg2->ciphertext2Len));

    ret = ret + (ssize_t) (cbor_encoded_len(&encoder));
    exit:
    return ret;
}

int format_msg2_decode(edhoc_msg2_t *msg2,
                       corr_t corr,
                       const cipher_suite_t *suite,
                       const uint8_t *msg2Buf,
                       size_t msg2Len) {
    int ret;
    const uint8_t *p;

#if defined(NANOCBOR)
    nanocbor_encoder_t decoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, msg2Buf, msg2Len);

    if (corr == NO_CORR || corr == CORR_2_3) {
        if (cbor_get_type(&decoder) == CBOR_BSTR) {
            CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg2->data2.cidi.bstr, &msg2->data2.cidi.length));
        } else if (cbor_get_type(&decoder) == CBOR_NINT) {
            CBOR_DEC_CHECK_RET(cbor_get_int8_t(&decoder, &msg2->data2.cidi.integer));
            msg2->data2.cidi.integer += 24;
            msg2->data2.cidi.length = 1;
        } else if (cbor_get_type(&decoder) == CBOR_UINT) {
            CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&decoder, (uint8_t *) &(msg2->data2.cidi.integer)));
            msg2->data2.cidi.integer += 24;
            msg2->data2.cidi.length = 1;
        } else {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }
    } else {
        msg2->data2.cidi.length = 0;
    }

    if (suite == NULL) {
        EDHOC_FAIL(EDHOC_ERR_CIPHERSUITE_UNAVAILABLE);
    }

    // (3) decode the ephemeral key
    if (suite->id == EDHOC_CIPHER_SUITE_0 || suite->id == EDHOC_CIPHER_SUITE_1) {
        msg2->data2.gY.kty = COSE_KTY_OCTET;
    } else {
        msg2->data2.gY.kty = COSE_KTY_EC2;
    }

    CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &p, &msg2->data2.gY.xLen));
    memcpy(msg2->data2.gY.x, p, msg2->data2.gY.xLen);


    // TODO: check validity key

    if (cbor_get_type(&decoder) == CBOR_BSTR) {
        CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg2->data2.cidr.bstr, &msg2->data2.cidr.length));
    } else if (cbor_get_type(&decoder) == CBOR_NINT) {
        CBOR_DEC_CHECK_RET(cbor_get_int8_t(&decoder, &msg2->data2.cidr.integer));
        msg2->data2.cidr.integer += 24;
        msg2->data2.cidr.length = 1;
    } else if (cbor_get_type(&decoder) == CBOR_UINT) {
        CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&decoder, (uint8_t *) &(msg2->data2.cidr.integer)));
        msg2->data2.cidr.integer += 24;
        msg2->data2.cidr.length = 1;
    } else {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg2->ciphertext2, &msg2->ciphertext2Len));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t format_msg3_encode(const edhoc_msg3_t *msg3, corr_t corr, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    if ((ret = format_data3_encode(&msg3->data3, corr, out, olen)) < 0) {
        EDHOC_FAIL(ret);
    }

    cbor_init_encoder(&encoder, out + ret, olen - ret);

    CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, msg3->ciphertext3, msg3->ciphertext3Len));

    ret = ret + (ssize_t) (cbor_encoded_len(&encoder));
    exit:
    return ret;
}

int format_msg3_decode(edhoc_msg3_t *msg3, corr_t corr, const uint8_t *msg3_buf, size_t msg3_len) {
    int ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t decoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, msg3_buf, msg3_len);

    if (corr == NO_CORR || corr == CORR_1_2) {
        if (cbor_get_type(&decoder) == CBOR_BSTR) {
            CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg3->data3.cidr.bstr, &msg3->data3.cidr.length));
        } else if (cbor_get_type(&decoder) == CBOR_NINT) {
            CBOR_DEC_CHECK_RET(cbor_get_int8_t(&decoder, &msg3->data3.cidr.integer));
            msg3->data3.cidr.integer += 24;
            msg3->data3.cidr.length = 1;
        } else if (cbor_get_type(&decoder) == CBOR_UINT) {
            CBOR_DEC_CHECK_RET(cbor_get_uint8_t(&decoder, (uint8_t *) &(msg3->data3.cidr.integer)));
            msg3->data3.cidr.integer += 24;
            msg3->data3.cidr.length = 1;
        } else {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }
    }

    CBOR_DEC_CHECK_RET(cbor_get_bstr(&decoder, &msg3->ciphertext3, &msg3->ciphertext3Len));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t format_data2_encode(const edhoc_data2_t *data2, corr_t corr, uint8_t *out, size_t olen) {
#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    ssize_t ret;
    cbor_init_encoder(&encoder, out, olen);

    // (1) Optionally encode the Initiator's connection identifier
    if (corr == NO_CORR || corr == CORR_2_3) {
        if (data2->cidi.length == 1 && data2->cidi.integer >= 0 && data2->cidi.integer <= 0x2f) {
            CBOR_ENC_CHECK_RET(cbor_put_int(&encoder, data2->cidi.integer - 24));
        } else {
            CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, data2->cidr.bstr, data2->cidr.length));
        }
    }

    // (2) Encode the Responder's public ephemeral key
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, data2->gY.x, data2->gY.xLen));

    // (3) Encode the Responder's connection identifier
    if (data2->cidr.length == 1 && data2->cidr.integer >= 0 && data2->cidr.integer <= 0x2f) {
        CBOR_ENC_CHECK_RET(cbor_put_int(&encoder, data2->cidr.integer - 24));
    } else {
        CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, data2->cidr.bstr, data2->cidr.length));
    }

    ret = (ssize_t) (cbor_encoded_len(&encoder));
    exit:
    return ret;
}

ssize_t format_data3_encode(const edhoc_data3_t *data3, corr_t corr, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&encoder, out, olen);

    // (1) Optionally encode the Initiator's connection identifier
    if (corr == NO_CORR || corr == CORR_1_2) {
        if (data3->cidr.length == 1 && data3->cidr.integer >= 0 && data3->cidr.integer <= 0x2f) {
            CBOR_ENC_CHECK_RET(cbor_put_int(&encoder, data3->cidr.integer - 24));
        } else {
            CBOR_ENC_CHECK_RET(cbor_put_bstr(&encoder, data3->cidr.bstr, data3->cidr.length));
        }
    }

    ret = (ssize_t) (cbor_encoded_len(&encoder));
    exit:
    return ret;
}

ssize_t format_info_encode(cose_algo_id_t id,
                           const uint8_t *th,
                           const char *label,
                           size_t len,
                           uint8_t *out,
                           size_t olen) {
#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&encoder, out, olen);

    cbor_put_array(&encoder, CBOR_ARRAY_INFO_LEN);
    cbor_put_int(&encoder, id);
    cbor_put_bstr(&encoder, th, EDHOC_DIGEST_SIZE);
    cbor_put_tstr(&encoder, label);
    cbor_put_uint(&encoder, len);

    return (ssize_t) cbor_encoded_len(&encoder);
}

ssize_t format_external_data_encode(const uint8_t *th,
                                    cred_t credCtx,
                                    cred_type_t credType,
                                    ad_cb_t ad2,
                                    uint8_t *out,
                                    size_t olen) {
    ssize_t ret, offset;
#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&enc, out, olen);
    cbor_put_bstr(&enc, th, EDHOC_DIGEST_SIZE);

    offset = (ssize_t) (cbor_encoded_len(&enc));

    if (credType == CRED_TYPE_CBOR_CERT) {
        memcpy(out + offset, ((c509_t *) credCtx)->raw.p, ((c509_t *) credCtx)->raw.length);
        offset += (ssize_t) (((c509_t *) credCtx)->raw.length);
    } else if (credType == CRED_TYPE_DER_CERT) {
#if defined(EDHOC_AUTH_X509_CERT)
#if defined(MBEDTLS)
        CBOR_ENC_CHECK_RET(
                cbor_put_bstr(&enc, ((mbedtls_x509_crt *) credCtx)->raw.p, ((mbedtls_x509_crt *) credCtx)->raw.len));
        offset = (ssize_t) (cbor_encoded_len(&enc));
#else
#error "No X509 backend enabled"
#endif
#endif
    } else if (credType == CRED_TYPE_RPK) {
        memcpy(out + offset, ((rpk_t *) credCtx)->raw.p, ((rpk_t *) credCtx)->raw.length);
        offset += (ssize_t) (((rpk_t *) credCtx)->raw.length);
    } else {
        EDHOC_FAIL(EDHOC_ERR_INVALID_CRED);
    }

    cbor_init_encoder(&enc, out + offset, olen - offset);
    if (ad2 != NULL) {
        //TODO: attach additional data
    }

    ret = (ssize_t) (offset + cbor_encoded_len(&enc));
    exit:
    return ret;
}

int format_plaintext23_decode(edhoc_plaintext23_t *plaintext, uint8_t *in, size_t ilen) {
    int ret;
    int8_t cborType;

#if defined(NANOCBOR)
    nanocbor_value_t dec;
    nanocbor_value_t _dec;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&dec, in, ilen);

    cbor_get_substream(&dec, &plaintext->credId->p, &plaintext->credId->length);
    cbor_init_decoder(&_dec, plaintext->credId->p, plaintext->credId->length);

    cborType = cbor_get_type(&_dec);

    if (cborType == CBOR_MAP) {
        EDHOC_CHECK_SUCCESS(cose_header_parse(plaintext->credId->map,
                                              plaintext->credId->p,
                                              plaintext->credId->length));
    } else {
        // if its a kid then there was a single item in the cose header
        plaintext->credId->map->key = COSE_HEADER_PARAM_KID;

        if (cborType == CBOR_BSTR) {
            CBOR_DEC_CHECK_RET(cbor_get_bstr(&_dec, &plaintext->credId->map[0].bstr, &plaintext->credId->map[0].len));
            plaintext->credId->map[0].valueType = COSE_HDR_VALUE_BSTR;
        } else if (cborType == CBOR_NINT || cborType == CBOR_UINT) {
            CBOR_DEC_CHECK_RET(cbor_get_int32_t(&_dec, &plaintext->credId->map->integer));
            plaintext->credId->map->integer += 24;
            plaintext->credId->map[0].valueType = COSE_HDR_VALUE_INT;
        } else {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }
    }

    CBOR_DEC_CHECK_RET(cbor_get_bstr(&dec, &plaintext->sigOrMac23, &plaintext->sigOrMac23Len));

    if (!cbor_at_end(&dec)) {
        CBOR_DEC_CHECK_RET(cbor_get_bstr(&dec, &plaintext->ad23, &plaintext->ad23Len));
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}


ssize_t format_plaintext23_encode(const edhoc_plaintext23_t *plaintext, uint8_t *out, size_t olen) {
    ssize_t ret, offset;

    int headerItems;

#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#else
#error "No CBOR backend enabled"
#endif

    offset = 0;

    // check length of cred id map
    headerItems = 0;
    for (int i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (plaintext->credId->map[i].key != COSE_HEADER_PARAM_RESERVED)
            headerItems++;
        else
            break;
    }

    // if KID and only item in header map, encode as BSTR_identifier
    if (headerItems == 1 && plaintext->credId->map[0].key == COSE_HEADER_PARAM_KID) {
        if (plaintext->credId->map[0].valueType == COSE_HDR_VALUE_BSTR) {
            cbor_init_encoder(&enc, out, olen);

            if (plaintext->credId->map[0].len == 1 && plaintext->credId->map[0].bstr[0] <= 0x2f) {
                cbor_put_int(&enc, (int8_t) (plaintext->credId->map[0].bstr[0] - 24));
            } else {
                CBOR_ENC_CHECK_RET(
                        cbor_put_bstr(&enc, plaintext->credId->map[0].bstr, plaintext->credId->map[0].len));
            }

            offset += (ssize_t) (cbor_encoded_len(&enc));
        }
    } else {
        if (plaintext->credId->length <= olen - offset) {
            memcpy(out, plaintext->credId->p, plaintext->credId->length);
            offset += (ssize_t) (plaintext->credId->length);
        } else {
            EDHOC_FAIL(EDHOC_ERR_BUFFER_OVERFLOW);
        }
    }

    cbor_init_encoder(&enc, out + offset, olen - offset);

    cbor_init_encoder(&enc, out + offset, olen - offset);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, plaintext->sigOrMac23, plaintext->sigOrMac23Len));

    if (plaintext->ad23Len != 0 && plaintext->ad23 != NULL) {
        CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, plaintext->ad23, plaintext->ad23Len));
    }

    ret = (ssize_t) (offset + cbor_encoded_len(&enc));
    exit:
    return ret;
}

ssize_t format_error_msg_encode(const edhoc_error_msg_t *errMsg, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&enc, out, olen);

    if (errMsg->cid.length != 0) {
        if (errMsg->cid.length == 1 && errMsg->cid.integer <= 0x2f) {
            CBOR_ENC_CHECK_RET(cbor_put_int(&enc, errMsg->cid.integer - 24));
        } else {
            CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, errMsg->cid.bstr, errMsg->cid.length));
        }
    }

    if (errMsg->diagnosticMsg == NULL && errMsg->suitesRLen == 0) {
        EDHOC_FAIL(ERR_EDHOC_ERROR_MESSAGE);
    }

    if (errMsg->diagnosticMsg != NULL) {
        CBOR_ENC_CHECK_RET(cbor_put_tstr(&enc, errMsg->diagnosticMsg));
    }

    if (errMsg->suitesRLen != 0) {
        CBOR_ENC_CHECK_RET(cbor_put_array(&enc, errMsg->suitesRLen));
        for (size_t i = 0; i < errMsg->suitesRLen; i++) {
            CBOR_ENC_CHECK_RET(cbor_put_uint(&enc, errMsg->suitesR[i]));
        }
    }

    ret = (ssize_t) (cbor_encoded_len(&enc));
    exit:
    return ret;

}
