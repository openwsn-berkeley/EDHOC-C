#ifndef EDHOC_CIPHER_SUITES_H
#define EDHOC_CIPHER_SUITES_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "cose.h"
#include "edhoc/edhoc.h"

typedef struct cipher_suite_t cipher_suite_t;
typedef struct method_t method_t;

struct cipher_suite_t{
    uint8_t id;
    const char* name;
    cose_kty_t key_type;
    cose_algo_t aead_algo;
    cose_algo_t hash_algo;
    cose_curve_t dh_curve;
    cose_algo_t sign_algo;
    cose_curve_t sign_curve;
    cose_algo_t app_aead;
    cose_algo_t app_hash;
};

struct method_t{
    uint8_t id;
    const char* name;
};

/**
 * @brief   Supported cipher suite list
 *
 * @return  Pointer to the list of supported ciphers
 */
const cipher_suite_t *edhoc_supported_suites(void);

/**
 * @brief   Return the length of the supported cipher suite list
 *
 * @return  Length of list of supported ciphers
 */
size_t edhoc_supported_suites_len(void);

/**
 * @brief   Return the length of the supported authentication method list
 *
 * @return  Length of list of the supported authentication methods
 */
size_t edhoc_auth_methods_len(void);

/**
 * @brief   Selects an authentication method and verifies its availability
 *
 * @return Pointer to auth method on success
 * @return NULL on failure
 */
const method_t *edhoc_auth_method_from_id(uint8_t method);

/**
 * @brief   Returns the cipher suite structure corresponding to the cipher suite ID.
 *
 * @param[in] id    Cipher suite identifier
 *
 * @return On success returns the cipher suite structure
 * @return On failure returns NULL
 */

/**
 * @brief   Selects a cipher suite and verifies its availability
 *
 * @return Pointer to cipher suite on success
 * @return NULL on failure
 */
const cipher_suite_t *edhoc_cipher_suite_from_id(uint8_t cipher_suite);

#endif /* EDHOC_CIPHER_SUITES_H */
