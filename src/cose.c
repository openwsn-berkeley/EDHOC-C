#include <string.h>
#include <edhoc/edhoc.h>

#if defined(MBEDTLS)
#include <mbedtls/sha256.h>
#elif defined(WOLFSSL)
#include <wolfssl/wolfcrypt/sha.h>
#else
#error "No cryptographic backend selected"
#endif

#include "crypto_internal.h"

#define CBOR_MAP_GET_INT_PARAM(cbor_obj, param_value, storage)          \
do{                                                                     \
    if((obj = cn_cbor_mapget_int((cbor_obj), (param_value))) != NULL){  \
        (storage) = (obj)->v.uint;                                      \
    }                                                                   \
} while(0)

#define CBOR_MAP_GET_BYTES_PARAM(cbor_obj, param_value, storage, len)   \
do {                                                                    \
    if((obj = cn_cbor_mapget_int((cbor_obj), (param_value))) != NULL){  \
        memcpy((storage), (obj)->v.bytes, (obj)->length);               \
        (len) = (obj)->length;                                          \
    }                                                                   \
} while(0)

void cose_key_init(cose_key_t *key) {
    memset(key, 0, sizeof(cose_key_t));

    key->kty = COSE_KTY_NONE;
    key->algo = COSE_ALGO_NONE;
    key->crv = COSE_EC_NONE;
}

int cose_key_len_from_alg(cose_algo_t alg) {
    int len;

    switch (alg) {
        case COSE_ALGO_AESCCM_16_128_128:
        case COSE_ALGO_AESCCM_16_64_128:
            len = 16;
            break;
        default:
            len = -1;
            break;
    }

    return len;
}

int cose_iv_len_from_alg(cose_algo_t alg) {
    int len;

    switch (alg) {
        case COSE_ALGO_AESCCM_16_128_128:
        case COSE_ALGO_AESCCM_16_64_128:
            len = 13;
            break;
        default:
            len = -1;
            break;
    }

    return len;
}

int cose_tag_len_from_alg(cose_algo_t alg){
    int len;

    switch (alg) {
        case COSE_ALGO_AESCCM_16_128_128:
            len = 16;
            break;
        case COSE_ALGO_AESCCM_16_64_128:
            len = 8;
            break;
        default:
            len = -1;
            break;
    }

    return len;
}

int cose_key_from_cbor(cose_key_t *key, const unsigned char *key_bytes, size_t key_len) {
    int ret;
    cn_cbor *obj;
    cn_cbor_errback cbor_err;
    cn_cbor *key_obj;

    // check if key is properly initialized
    if (key->kty != COSE_KTY_NONE || key->algo != COSE_ALGO_NONE || key->crv != COSE_EC_NONE) {
        ret = EDHOC_ERR_INVALID_CBOR_KEY;
        goto exit;
    }

    if ((key_obj = cn_cbor_decode(key_bytes, key_len, &cbor_err)) == NULL) {
        ret = EDHOC_ERR_INVALID_CBOR_KEY;
        goto exit;
    }

    if ((obj = cn_cbor_mapget_int(key_obj, COSE_KEY_COMMON_PARAM_KTY)) == NULL) {
        ret = EDHOC_ERR_INVALID_CBOR_KEY;
        goto exit;
    } else {
        key->kty = obj->v.uint;
    }

    CBOR_MAP_GET_INT_PARAM(key_obj, COSE_KEY_COMMON_PARAM_ALGO, key->algo);

    switch (key->kty) {
        case COSE_KTY_OCTET:
            CBOR_MAP_GET_INT_PARAM(key_obj, COSE_KEY_OKP_PARAM_CRV, key->crv);
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_OKP_PARAM_X, key->x, key->x_len);
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_OKP_PARAM_D, key->d, key->d_len);
            break;
        case COSE_KTY_EC2:
            CBOR_MAP_GET_INT_PARAM(key_obj, COSE_KEY_EC2_PARAM_CRV, key->crv);
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_EC2_PARAM_X, key->x, key->x_len);
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_EC2_PARAM_Y, key->y, key->y_len);
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_EC2_PARAM_D, key->d, key->d_len);
            break;
        case COSE_KTY_SYMM:
            CBOR_MAP_GET_BYTES_PARAM(key_obj, COSE_KEY_SYMMETRIC_PARAM_K, key->k, key->k_len);
            break;
        default:
            ret = EDHOC_ERR_INVALID_CBOR_KEY;
            goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t cose_x5t_attribute(cose_algo_t hash, const uint8_t *cert, size_t cert_len, uint8_t *out, size_t olen) {
    ssize_t ret;
    size_t hash_len;
    uint8_t digest[COSE_DIGEST_LEN];
    cn_cbor_errback err;
    cn_cbor *cbor_array, *cbor_map, *cbor_int, *cbor_digest;

#if defined(MBEDTLS)
    // always SHA-256 (only hash algorithm supported by the EDHOC cipher suites)
    mbedtls_sha256_context cert_digest_ctx;
#elif defined(WOLFSSL)
    wc_Sha cert_digest_ctx;
#else
#error "No cryptographic backend selected"
#endif

    if ((ret = crypt_hash_init(&cert_digest_ctx)) != EDHOC_SUCCESS) {
        goto exit;
    }

    if ((ret = crypt_hash_update(&cert_digest_ctx, cert, cert_len)) != EDHOC_SUCCESS) {
        goto exit;
    }

    if ((ret = crypt_hash_finish(&cert_digest_ctx, digest)) != EDHOC_SUCCESS) {
        goto exit;
    }

    if (hash == COSE_ALGO_SHA256_64) {
        hash_len = 8;
    } else {
        hash_len = sizeof(digest);
    }

    if ((cbor_array = cn_cbor_array_create(&err)) == NULL) {
        ret = EDHOC_ERR_CBOR_ENCODING;
        goto exit;
    }

    if ((cbor_int = cn_cbor_int_create(COSE_ALGO_SHA256_64, &err)) == NULL) {
        ret = EDHOC_ERR_CBOR_ENCODING;
        goto exit;
    } else {
        cn_cbor_array_append(cbor_array, cbor_int, &err);
    }

    if ((cbor_digest = cn_cbor_data_create(digest, hash_len, &err)) == NULL) {
        ret = EDHOC_ERR_CBOR_ENCODING;
        goto exit;
    } else {
        cn_cbor_array_append(cbor_array, cbor_digest, &err);
    }

    if ((cbor_map = cn_cbor_map_create(&err)) == NULL) {
        ret = EDHOC_ERR_CBOR_ENCODING;
        goto exit;
    } else {
        cn_cbor_mapput_int(cbor_map, COSE_KEY_COMMON_PARAM_X5T, cbor_array, &err);
    }

    if ((ret = cn_cbor_encoder_write(out, 0, olen, cbor_map)) < EDHOC_SUCCESS) {
        ret = EDHOC_ERR_CBOR_ENCODING;
        goto exit;
    }

    exit:
    return ret;

}
