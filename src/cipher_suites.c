#include "edhoc/edhoc.h"
#include "edhoc/cipher_suites.h"

static const method_t auth_methods_supported[] =
        {
#if defined(EDHOC_AUTH_METHODS)
                EDHOC_AUTH_METHODS
#else
                EDHOC_AUTH_SIGN_SIGN,   // supported ciphers ...
                EDHOC_AUTH_SIGN_STATIC,
                EDHOC_AUTH_STATIC_SIGN,
                EDHOC_AUTH_STATIC_STATIC
#endif
        };

static const cipher_suite_t ciphersuites_supported[] =
        {
#if defined(EDHOC_CIPHER_SUITES)
                EDHOC_CIPHER_SUITES
#else
                EDHOC_CIPHER_SUITE_0,   // supported ciphers ...
                EDHOC_CIPHER_SUITE_1,
                EDHOC_CIPHER_SUITE_2,
                EDHOC_CIPHER_SUITE_3
#endif
        };

const cipher_suite_t *edhoc_supported_suites(void) {

    if (sizeof(ciphersuites_supported) >= 1) {
        return ciphersuites_supported;
    } else {
        return NULL;
    }
}

const cipher_suite_t *edhoc_auth_methods(void) {

    if (sizeof(auth_methods_supported) >= 1) {
        return auth_methods_supported;
    } else {
        return NULL;
    }
}

size_t edhoc_supported_suites_len(void) {
    return sizeof(ciphersuites_supported);
}

size_t edhoc_auth_methods_len(void) {
    return sizeof(auth_methods_supported);
}

const method_t *edhoc_select_auth_method(method_t method) {
    for (size_t i = 0; i < edhoc_auth_methods_len(); i++) {
        if (method == auth_methods_supported[i]) {
            return &auth_methods_supported[i];
        }
    }

    return NULL;
}

const method_t *edhoc_select_suite(cipher_suite_t suite) {
    for (size_t i = 0; i < edhoc_supported_suites_len(); i++) {
        if (suite == ciphersuites_supported[i]) {
            return &ciphersuites_supported[i];
        }
    }

    return NULL;
}

cose_kty_t edhoc_kty_from_suite(cipher_suite_t suite) {
    cose_kty_t kty;

    switch (suite) {
        case EDHOC_CIPHER_SUITE_0:
        case EDHOC_CIPHER_SUITE_1:
            kty = COSE_KTY_OCTET;
            break;
        case EDHOC_CIPHER_SUITE_2:
        case EDHOC_CIPHER_SUITE_3:
            kty = COSE_KTY_EC2;
            break;
        default:
            kty = COSE_KTY_NONE;
            break;
    }

    return kty;
}

cose_algo_t edhoc_aead_from_suite(cipher_suite_t suite){
    cose_algo_t aead;

    switch (suite) {
        case EDHOC_CIPHER_SUITE_0:
        case EDHOC_CIPHER_SUITE_2:
            aead = COSE_ALGO_AESCCM_16_64_128;
            break;
        case EDHOC_CIPHER_SUITE_1:
        case EDHOC_CIPHER_SUITE_3:
            aead = COSE_ALGO_AESCCM_16_128_128;
            break;
        default:
            aead = COSE_ALGO_NONE;
            break;
    }

    return aead;
}

cose_algo_t edhoc_app_aead_from_suite(cipher_suite_t suite){
    return COSE_ALGO_AESCCM_16_64_128;
}

cose_curve_t edhoc_dh_curve_from_suite(cipher_suite_t suite) {
    cose_curve_t crv;

    switch (suite) {
        case EDHOC_CIPHER_SUITE_0:
        case EDHOC_CIPHER_SUITE_1:
            crv = COSE_EC_CURVE_X25519;
            break;
        case EDHOC_CIPHER_SUITE_2:
        case EDHOC_CIPHER_SUITE_3:
            crv = COSE_EC_CURVE_P256;
            break;
        default:
            crv = COSE_EC_NONE;
            break;
    }

    return crv;
}

cose_curve_t edhoc_sign_curve_from_suite(cipher_suite_t suite) {
    cose_curve_t crv;

    switch (suite) {
        case EDHOC_CIPHER_SUITE_0:
        case EDHOC_CIPHER_SUITE_1:
            crv = COSE_EC_CURVE_ED25519;
            break;
        case EDHOC_CIPHER_SUITE_2:
        case EDHOC_CIPHER_SUITE_3:
            crv = COSE_EC_CURVE_P256;
            break;
        default:
            crv = COSE_EC_NONE;
            break;
    }

    return crv;
}

cose_algo_t edhoc_hash_from_suite(cipher_suite_t suite) {
    cose_algo_t hash;

    switch (suite) {
        case EDHOC_CIPHER_SUITE_0:
        case EDHOC_CIPHER_SUITE_1:
        case EDHOC_CIPHER_SUITE_2:
        case EDHOC_CIPHER_SUITE_3:
            hash = COSE_ALGO_SHA256;
            break;
        default:
            hash = COSE_ALGO_NONE;
            break;
    }

    return hash;
}
