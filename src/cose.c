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
#include "cbor_internal.h"

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

int cose_tag_len_from_alg(cose_algo_t alg) {
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

int cose_key_from_cbor(cose_key_t *key, const uint8_t *key_bytes, size_t key_len) {
    int ret;
    const uint8_t *pt = NULL;

    // check if key is properly initialized
    if (key->kty != COSE_KTY_NONE || key->algo != COSE_ALGO_NONE || key->crv != COSE_EC_NONE) {
        ret = EDHOC_ERR_INVALID_CBOR_KEY;
        goto exit;
    }

    cbor_map_get_int_int(COSE_KEY_COMMON_PARAM_KTY, (int *) &key->kty, key_bytes, 0, key_len);
    cbor_map_get_int_int(COSE_KEY_COMMON_PARAM_ALGO, (int *) &key->algo, key_bytes, 0, key_len);

    switch (key->kty) {
        case COSE_KTY_OCTET:
            cbor_map_get_int_int(COSE_KEY_OKP_PARAM_CRV, (int *) &key->crv, key_bytes, 0, key_len);

            cbor_map_get_int_bytes(COSE_KEY_OKP_PARAM_X, &pt, &key->x_len, key_bytes, 0, key_len);
            if (pt != NULL && key->x_len > 0)
                memcpy(key->x, pt, key->x_len);

            cbor_map_get_int_bytes(COSE_KEY_OKP_PARAM_D, &pt, &key->d_len, key_bytes, 0, key_len);
            if (pt != NULL && key->d_len > 0)
                memcpy(key->d, pt, key->d_len);

            break;
        case COSE_KTY_EC2:
            cbor_map_get_int_int(COSE_KEY_EC2_PARAM_CRV, (int *) &key->crv, key_bytes, 0, key_len);

            cbor_map_get_int_bytes(COSE_KEY_EC2_PARAM_X, &pt, &key->x_len, key_bytes, 0, key_len);
            if (pt != NULL && key->x_len > 0)
                memcpy(key->x, pt, key->x_len);

            cbor_map_get_int_bytes(COSE_KEY_EC2_PARAM_Y, &pt, &key->y_len, key_bytes, 0, key_len);
            if (pt != NULL && key->y_len > 0)
                memcpy(key->y, pt, key->y_len);

            cbor_map_get_int_bytes(COSE_KEY_EC2_PARAM_D, &pt, &key->d_len, key_bytes, 0, key_len);
            if (pt != NULL && key->d_len > 0)
                memcpy(key->d, pt, key->d_len);

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
    int ret;
    ssize_t size, written;
    size_t hash_len;
    uint8_t digest[COSE_DIGEST_LEN] = {0};

    size = 0;

#if defined(MBEDTLS)
    // always SHA-256 (only hash algorithm supported by the EDHOC cipher suites)
    mbedtls_sha256_context cert_digest_ctx;
#elif defined(WOLFSSL)
    wc_Sha cert_digest_ctx;
#else
#error "No cryptographic backend selected"
#endif

    EDHOC_CHECK_SUCCESS(crypt_hash_init(&cert_digest_ctx));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&cert_digest_ctx, cert, cert_len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&cert_digest_ctx, digest));

    if (hash == COSE_ALGO_SHA256_64) {
        hash_len = 8;
    } else {
        hash_len = sizeof(digest);
    }

    CBOR_CHECK_RET(cbor_create_map(out, 1, size, olen));
    CBOR_CHECK_RET(cbor_int_encode(COSE_KEY_COMMON_PARAM_X5T, out, size, olen));
    CBOR_CHECK_RET(cbor_create_array(out, 2, size, olen));
    CBOR_CHECK_RET(cbor_int_encode(COSE_ALGO_SHA256_64, out, size, olen));
    CBOR_CHECK_RET(cbor_bytes_encode(digest, hash_len, out, size, olen));

    ret = size;
    exit:
    return ret;
}
