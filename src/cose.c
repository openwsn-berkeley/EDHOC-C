#include <string.h>
#include "edhoc/edhoc.h"

#if defined(NANOCBOR)

#include "nanocbor/nanocbor.h"

#endif

#include "cbor.h"
#include "edhoc/cose.h"
#include "crypto.h"

static const cose_aead_t cose_aead_cipher_info[] = {
#if defined(EDHOC_CIPHER_SUITE_0_ENABLED) || defined(EDHOC_CIPHER_SUITE_2_ENABLED)
        {
                COSE_ALGO_AESCCM_16_64_128,
                "COSE_ALGO_AESCCM_16_64_128",
                16,
                13,
                8,
        },
#endif
#if defined(EDHOC_CIPHER_SUITE_1_ENABLED) || defined(EDHOC_CIPHER_SUITE_3_ENABLED)
        {
                COSE_ALGO_AESCCM_16_128_128,
                "COSE_ALGO_AESCCM_16_128_128",
                16,
                13,
                16,
        }
#endif
};

static const cose_sign_t cose_signature_algorithm_info[] = {
#if defined(EDHOC_CIPHER_SUITE_0_ENABLED) || defined(EDHOC_CIPHER_SUITE_1_ENABLED)
        {
                COSE_ALGO_EDDSA,
                "COSE_ALGO_EDDSA",
        },
#endif
#if defined(EDHOC_CIPHER_SUITE_2_ENABLED) || defined(EDHOC_CIPHER_SUITE_3_ENABLED)
        {
                COSE_ALGO_ES256,
                "COSE_ALGO_ES256",
        },
#endif
};

void cose_key_init(cose_key_t *key) {
    memset(key, 0, sizeof(cose_key_t));

    key->kty = COSE_KTY_NONE;
    key->algo = COSE_ALGO_NONE;
}

int cose_symmetric_key_from_buffer(cose_key_t *key, uint8_t *k, size_t kLen) {

    key->kty = COSE_KTY_SYMMETRIC;

    if (kLen != 16 && kLen != 24 && kLen != 32)
        return EDHOC_ERR_INVALID_KEY;

    memcpy(key->k, k, kLen);
    key->kLen = kLen;

    return EDHOC_SUCCESS;
}

int cose_key_from_cbor(cose_key_t *key, const uint8_t *in, size_t ilen) {
    int ret;
    const uint8_t *p;
    int8_t found_x, found_d;

#if defined(NANOCBOR)
    nanocbor_value_t decoder;
#elif defined(EMPTY_CBOR)
    int decoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, in, ilen);

    if (cbor_get_type(&decoder) != CBOR_MAP) {
        EDHOC_FAIL(EDHOC_ERR_INVALID_KEY);
    }

    // COSE KTY element MUST be in the CBOR map
    CBOR_DEC_CHECK_RET(cbor_map_from_int_int(&decoder, COSE_KEY_PARAM_KTY, (int8_t *) &key->kty));

    // algorithm parameter is optional
    cbor_map_from_int_int(&decoder, COSE_KEY_PARAM_ALGO, (int8_t *) &key->algo);

    switch (key->kty) {
        case COSE_KTY_OCTET:
            // mandatory parameter of the COSE Key
            cbor_init_decoder(&decoder, in, ilen);
            CBOR_DEC_CHECK_RET(cbor_map_from_int_int(&decoder, COSE_KEY_OKP_PARAM_CRV, (int8_t *) &key->crv));

            // reset decoder
            cbor_init_decoder(&decoder, in, ilen);
            found_x = cbor_map_from_int_bytes(&decoder, COSE_KEY_OKP_PARAM_X, &p, &key->xLen);
            if (found_x == 0)
                memcpy(key->x, p, key->xLen);

            // reset decoder
            cbor_init_decoder(&decoder, in, ilen);
            found_d = cbor_map_from_int_bytes(&decoder, COSE_KEY_OKP_PARAM_D, &p, &key->dLen);
            if (found_d == 0)
                memcpy(key->d, p, key->dLen);

            // we must have either the public part or private part, otherwise this is an invalid COSE key
            if (found_d == CBOR_FAILED && found_x == CBOR_FAILED) {
                EDHOC_FAIL(EDHOC_ERR_INVALID_KEY);
            }

            break;
        default:
            ret = EDHOC_ERR_INVALID_KEY;
            goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

void cose_encrypt0_init(cose_encrypt0_t *coseMsgCtx,
                        uint8_t *payload,
                        size_t payloadLen,
                        const cose_aead_t *aeadCipher,
                        uint8_t *tag) {

    memset((cose_encrypt0_t *) coseMsgCtx, 0, sizeof(cose_encrypt0_t));

    cose_header_init(((cose_encrypt0_t *) coseMsgCtx)->base.protected);

    ((cose_encrypt0_t *) coseMsgCtx)->base.payload = payload;
    ((cose_encrypt0_t *) coseMsgCtx)->base.payloadLen = payloadLen;
    ((cose_encrypt0_t *) coseMsgCtx)->aeadCipher = aeadCipher;
    ((cose_encrypt0_t *) coseMsgCtx)->authTag = tag;
}

void cose_sign1_init(cose_sign1_t *coseMsgCtx,
                     uint8_t *payload,
                     size_t payloadLen,
                     const cose_sign_t *signAlgorithm,
                     uint8_t *signature) {
    memset((cose_sign1_t *) coseMsgCtx, 0, sizeof(cose_sign1_t));

    cose_header_init(((cose_sign1_t *) coseMsgCtx)->base.protected);

    ((cose_sign1_t *) coseMsgCtx)->base.payload = payload;
    ((cose_sign1_t *) coseMsgCtx)->base.payloadLen = payloadLen;
    ((cose_sign1_t *) coseMsgCtx)->signAlgorithm = signAlgorithm;
    ((cose_sign1_t *) coseMsgCtx)->signature = signature;
}

void cose_header_init(cose_header_t *header) {
    memset(header, 0, sizeof(cose_header_t));

    for (int i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        header[i].key = COSE_HEADER_PARAM_RESERVED;
    }
}

static int internal_header_serialize(void *encoder, cose_header_t *header, ssize_t *len, bool sizeOnly) {
    int res;
    int headerItems;

    *len = 0;

    // count used header items
    headerItems = 0;
    for (int i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (header[i].key != COSE_HEADER_PARAM_RESERVED) {
            headerItems++;
        }
    }

    if (headerItems == 0)
        return EDHOC_SUCCESS;

    res = 0;

    cbor_put_map(encoder, headerItems);
    for (int i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (header[i].key != COSE_HEADER_PARAM_RESERVED) {
            // encode key
            res -= cbor_put_int8_t(encoder, header[i].key);

            // encode value
            switch (header[i].valueType) {
                case COSE_HDR_VALUE_INT:
                    res -= cbor_put_int8_t(encoder, header->integer);
                    break;
                case COSE_HDR_VALUE_BSTR:
                    res -= cbor_put_bstr(encoder, header->bstr, header->len);
                    break;
                case COSE_HDR_VALUE_TSTR:
                    res -= cbor_put_tstr(encoder, header->tstr);
                    break;
                case COSE_HDR_VALUE_CERTHASH:
                    res -= cbor_put_array(encoder, 2);
                    res -= cbor_put_int8_t(encoder, header->certHash.identifier);
                    res -= cbor_put_bstr(encoder, header->certHash.value, header->certHash.length);
                    break;
                default:
                    res = EDHOC_ERR_CBOR_ENCODING;
                    break;
            }

            if (sizeOnly == false && res != CBOR_SUCCESS)
                return EDHOC_ERR_CBOR_ENCODING;
        }
    }

    *len = cbor_encoded_len(encoder);

    return EDHOC_SUCCESS;
}

ssize_t cose_header_serialized_len(cose_header_t *header) {
    ssize_t ret, tmp;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#elif defined(EMPTY_CBOR)
    int encoder;
#else
#error "No CBOR backend enabled"
#endif

    // compute the total length of the serialized header
    cbor_init_encoder(&encoder, NULL, 0);
    EDHOC_CHECK_SUCCESS(internal_header_serialize(&encoder, header, &tmp, true));

    ret = tmp;
    exit:
    return ret;
}

int cose_header_serialize(cose_header_t *header, uint8_t *out, size_t olen) {
    ssize_t ret, tmp;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#elif defined(EMPTY_CBOR)
    int encoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_encoder(&encoder, out, olen);
    EDHOC_CHECK_SUCCESS(internal_header_serialize(&encoder, header, &tmp, false));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int cose_header_parse(cose_header_t *header, const uint8_t *in, size_t ilen) {
    int ret;

    int headerItemIndex;
    int8_t headerValueType;


    size_t _tmp;

#if defined(NANOCBOR)
    nanocbor_value_t decoder;
    nanocbor_value_t map;
    nanocbor_value_t array;
#elif defined(EMPTY_CBOR)
    int decoder;
    int map;
    int array;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, in, ilen);

    if (cbor_get_type(&decoder) != CBOR_MAP) {
        return EDHOC_ERR_INVALID_CRED_ID;
    }


    headerItemIndex = 0;

    if (cbor_start_decoding_map(&decoder, &map) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    while (!cbor_at_end(&map) && headerItemIndex < COSE_MAX_HEADER_ITEMS) {
        // fetch key
        if (cbor_get_int32_t(&map, (int32_t *) &header[headerItemIndex].key) < 0) {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }

        // fetch value
        headerValueType = cbor_get_type(&map);
        if (headerValueType == CBOR_NINT || headerValueType == CBOR_UINT) {
            if (cbor_get_int32_t(&map, &header[headerItemIndex].integer) < 0) {
                EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
            }

            header[headerItemIndex].valueType = COSE_HDR_VALUE_INT;
        } else if (headerValueType == CBOR_BSTR) {
            cbor_get_bstr(&map, &header[headerItemIndex].bstr, &header[headerItemIndex].len);
            header[headerItemIndex].valueType = COSE_HDR_VALUE_BSTR;
        } else if (headerValueType == CBOR_TSTR) {
            cbor_get_tstr(&map, (const uint8_t **) &header[headerItemIndex].tstr, &_tmp);
            header[headerItemIndex].valueType = COSE_HDR_VALUE_TSTR;
        } else if (headerValueType == CBOR_ARRAY) {
            if (cbor_start_decoding_array(&map, &array)) {
                EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
            }

            if (cbor_get_int32_t(&array, &header[headerItemIndex].certHash.identifier) < 0) {
                EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
            }

            if (cbor_get_bstr(&array,
                              &header[headerItemIndex].certHash.value,
                              &header[headerItemIndex].certHash.length) != CBOR_SUCCESS) {
                EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
            }
            // once done parse skip the array element.
            cbor_skip(&map);

            header[headerItemIndex].valueType = COSE_HDR_VALUE_CERTHASH;
        } else {
            return EDHOC_ERR_CBOR_DECODING;
        }

        headerItemIndex++;
    }

    if (headerItemIndex >= COSE_MAX_HEADER_ITEMS)
        ret = EDHOC_ERR_CBOR_DECODING;
    else
        ret = EDHOC_SUCCESS;

    exit:
    return ret;
}

const cose_aead_t *cose_algo_get_aead_info(cose_algo_id_t id) {

    for (size_t i = 0; i < sizeof(cose_aead_cipher_info) / sizeof(cose_aead_t); i++) {
        if (id == cose_aead_cipher_info[i].id) {
            return &cose_aead_cipher_info[i];
        }
    }

    return NULL;
}

const cose_sign_t *cose_algo_get_sign_info(cose_algo_id_t id) {

    for (size_t i = 0; i < sizeof(cose_signature_algorithm_info) / sizeof(cose_sign_t); i++) {
        if (id == cose_signature_algorithm_info[i].id) {
            return &cose_signature_algorithm_info[i];
        }
    }

    return NULL;
}

void cose_message_set_external_aad(cose_message_t *coseMsgCtx, const uint8_t *extAad, size_t extAadLen) {
    coseMsgCtx->extAad = extAad;
    coseMsgCtx->extAadLen = extAadLen;
}

void cose_message_set_payload(cose_message_t *coseMsgCtx, const uint8_t *payload, size_t len) {
    coseMsgCtx->payload = (uint8_t *) payload;
    coseMsgCtx->payloadLen = len;
}

void cose_message_set_algo(cose_message_t *coseMsgCtx, cose_algo_id_t algoID) {
    const cose_aead_t *aeadCipher;
    const cose_sign_t *signAlg;

    if ((aeadCipher = cose_algo_get_aead_info(algoID)) != NULL) {
        ((cose_encrypt0_t *) coseMsgCtx)->aeadCipher = aeadCipher;
        return;
    }

    if ((signAlg = cose_algo_get_sign_info(algoID)) != NULL) {
        ((cose_sign1_t *) coseMsgCtx)->signAlgorithm = signAlg;
        return;
    }
}

int cose_message_set_protected_hdr(cose_message_t *coseMsgCtx, cose_header_t *header) {
    int i;
    for (i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (coseMsgCtx->protected[i].key == COSE_HEADER_PARAM_RESERVED) {
            memcpy(&coseMsgCtx->protected[i], header, sizeof(cose_header_t));
            break;
        }
    }

    if (i == COSE_MAX_HEADER_ITEMS)
        return EDHOC_ERR_BUFFER_OVERFLOW;
    else
        return EDHOC_SUCCESS;
}

int cose_sign1_sign(cose_sign1_t *coseMsgCtx, const cose_key_t *key) {
    ssize_t toBeSignedLen;
    uint8_t toBeSigned[EDHOC_TOBESIGNED_SIZE];

    // debugging purposes
    memset(toBeSigned, 0, EDHOC_TOBESIGNED_SIZE);

    if (key->kty != COSE_KTY_OCTET && key->kty != COSE_KTY_EC2) {
        return EDHOC_ERR_INVALID_KEY;
    }

    if ((toBeSignedLen = cose_sign1_create_to_be_signed(coseMsgCtx, toBeSigned, sizeof(toBeSigned))) < 0) {
        return toBeSignedLen;
    }

    coseMsgCtx->sigLen = EDHOC_SIGNATURE23_SIZE;
    return crypt_sign(key, toBeSigned, toBeSignedLen, coseMsgCtx->signature, &coseMsgCtx->sigLen);
}

int cose_encrypt0_decrypt(cose_encrypt0_t *coseMsgCtx, const cose_key_t *key, const uint8_t *iv, size_t ivLen) {
    ssize_t addAuthDataLen;
    uint8_t addAuthData[EDHOC_ASSOCIATED_DATA_SIZE];

    // debugging purposes
    memset(addAuthData, 0, EDHOC_ASSOCIATED_DATA_SIZE);

    if (key->kty != COSE_KTY_SYMMETRIC) {
        return EDHOC_ERR_INVALID_KEY;
    }

    if ((addAuthDataLen = cose_encrypt0_create_adata(coseMsgCtx, addAuthData, sizeof(addAuthData))) < 0) {
        return addAuthDataLen;
    }

    return crypt_decrypt(key,
                         iv,
                         ivLen,
                         addAuthData,
                         addAuthDataLen,
                         coseMsgCtx->base.payload,
                         coseMsgCtx->base.payload,
                         coseMsgCtx->base.payloadLen,
                         coseMsgCtx->authTag,
                         coseMsgCtx->aeadCipher->tagLength);
}

int cose_encrypt0_encrypt(cose_encrypt0_t *coseMsgCtx, const cose_key_t *key, const uint8_t *iv, size_t ivLen) {
    ssize_t addAuthDataLen;
    uint8_t addAuthData[EDHOC_ASSOCIATED_DATA_SIZE];

    // debugging purposes
    memset(addAuthData, 0, EDHOC_ASSOCIATED_DATA_SIZE);

    if (key->kty != COSE_KTY_SYMMETRIC) {
        return EDHOC_ERR_INVALID_KEY;
    }

    if ((addAuthDataLen = cose_encrypt0_create_adata(coseMsgCtx, addAuthData, sizeof(addAuthData))) < 0) {
        return addAuthDataLen;
    }

    return crypt_encrypt(key,
                         iv,
                         ivLen,
                         addAuthData,
                         addAuthDataLen,
                         coseMsgCtx->base.payload,
                         coseMsgCtx->base.payload,
                         coseMsgCtx->base.payloadLen,
                         coseMsgCtx->authTag,
                         coseMsgCtx->aeadCipher->tagLength);
}

static ssize_t cose_message_base_structure(cose_message_t *coseMsgCtx,
                                           int elements,
                                           const char *label,
                                           uint8_t *out,
                                           size_t olen) {
    ssize_t ret, offset, coseHdrLen;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#elif defined(EMPTY_CBOR)
    int encoder;
#endif

    cbor_init_encoder(&encoder, out, olen);

    if (cbor_put_array(&encoder, elements) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_ENCODING);
    }

    if (cbor_put_tstr(&encoder, label) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_ENCODING);
    }

    offset = cbor_encoded_len(&encoder);

    /* add COSE protected header */
    cbor_init_encoder(&encoder, out + offset, olen - offset);
    coseHdrLen = cose_header_serialized_len(&coseMsgCtx->protected[0]);
    cbor_start_bstr(&encoder, coseHdrLen);
    offset += cbor_encoded_len(&encoder);

    if (coseHdrLen != 0) {
        if (cose_header_serialize(&coseMsgCtx->protected[0], out + offset, olen - offset) != EDHOC_SUCCESS) {
            return EDHOC_ERR_CBOR_ENCODING;
        } else {
            offset += coseHdrLen;
        }
    }

    cbor_init_encoder(&encoder, out + offset, olen - offset);
    if (cbor_put_bstr(&encoder, coseMsgCtx->extAad, coseMsgCtx->extAadLen) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_ENCODING);
    }

    ret = offset + cbor_encoded_len(&encoder);
    exit:
    return ret;
}

ssize_t cose_encrypt0_create_adata(cose_encrypt0_t *coseMsgCtx, uint8_t *out, size_t olen) {
    return cose_message_base_structure(&coseMsgCtx->base, 3, "Encrypt0", out, olen);
}

ssize_t cose_sign1_create_to_be_signed(cose_sign1_t *coseMsgCtx, uint8_t *out, size_t olen) {
    ssize_t ret;

#if defined(NANOCBOR)
    nanocbor_encoder_t encoder;
#elif defined(EMPTY_CBOR)
    int encoder;
#endif

    cbor_init_encoder(&encoder, out, olen);

    ret = cose_message_base_structure(&coseMsgCtx->base, 4, "Signature1", out, olen);

    cbor_init_encoder(&encoder, out + ret, olen - ret);
    if (cbor_put_bstr(&encoder, coseMsgCtx->base.payload, coseMsgCtx->base.payloadLen) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_ENCODING);
    }

    ret += cbor_encoded_len(&encoder);
    exit:
    return ret;
}
