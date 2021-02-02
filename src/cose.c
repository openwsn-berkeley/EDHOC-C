#include <string.h>
#include <edhoc/edhoc.h>

#include "cbor.h"
#include "cose.h"

static const aead_info_t cose_aead_cipher_info[] = {
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

void cose_key_init(cose_key_t *key) {
    memset(key, 0, sizeof(cose_key_t));

    key->kty = COSE_KTY_NONE;
    key->algo = COSE_ALGO_NONE;
    key->crv = COSE_EC_NONE;
}

const aead_info_t *cose_aead_info_from_id(uint8_t aead_id){

    for (size_t i = 0; i < sizeof(cose_aead_cipher_info) / sizeof(aead_info_t); i++) {
        if (aead_id == cose_aead_cipher_info[i].id) {
            return &cose_aead_cipher_info[i];
        }
    }

    return NULL;
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
#if defined(EDHOC_CIPHER_SUITE_2_ENABLED)
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
#endif
        default:
            ret = EDHOC_ERR_INVALID_CBOR_KEY;
            goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}