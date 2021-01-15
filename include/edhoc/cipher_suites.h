#ifndef EDHOC_CIPHER_SUITES_H
#define EDHOC_CIPHER_SUITES_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "edhoc/edhoc.h"

#define EDHOC_CIPHER_SUITE_0        ((cipher_suite_t)0)
#define EDHOC_CIPHER_SUITE_1        ((cipher_suite_t)1)
#define EDHOC_CIPHER_SUITE_2        ((cipher_suite_t)2)
#define EDHOC_CIPHER_SUITE_3        ((cipher_suite_t)3)

#define EDHOC_AUTH_SIGN_SIGN        ((method_t)0)
#define EDHOC_AUTH_SIGN_STATIC      ((method_t)1)
#define EDHOC_AUTH_STATIC_SIGN      ((method_t)2)
#define EDHOC_AUTH_STATIC_STATIC    ((method_t)3)

/**
 * @brief   Return the supported cipher suite list
 *
 * @return  Const pointer to the list of supported ciphers
 */
const cipher_suite_t *edhoc_supported_suites(void);

/**
 * @brief   Return the supported authentication methods
 *
 * @return  Const pointer to the list of supported authenication methods
 */
const method_t *edhoc_auth_methods(void);

/**
 * @brief   Return the length of the supported cipher suite list
 *
 * @return  Length of list of supported ciphers
 */
size_t edhoc_supported_suites_len(void);

/**
 * @brief   Selects a cipher suite and verifies its availability
 *
 * @return Pointer to cipher suite on success
 * @return NULL on failure
 */
const cipher_suite_t *edhoc_select_suite(cipher_suite_t suite);

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
const method_t *edhoc_select_auth_method(method_t method);

/**
 * @brief Get the COSE curve for the DH exchange from an EDHOC cipher suite
 *
 * @param[in]   suite   An EDHOC cipher suite
 *
 * @return  On success a COSE curve used in the provided EDHOC cipher suite
 * @return On failure COSE_EC_NONE
 **/
cose_curve_t edhoc_dh_curve_from_suite(cipher_suite_t suite);

/*
 * @brief Get the COSE AEAD identifier from the EDHOC cipher suite
 *
 * @param[in]   suite   An EDHOC cipher suite
 *
 * @return  On success, A COSE AEAD identifier used in this cipher suite.
 * @return  On failure, COSE_ALGO_NONE
 */
cose_algo_t edhoc_aead_from_suite(cipher_suite_t suite);

/*
 * @brief Get the COSE key type from the EDHOC cipher suite
 *
 * @param[in]   suite   An EDHOC cipher suite
 *
 * @return On success, a COSE key type appropriate for use with this cipher suite.
 * @return On failure, COSE_KTY_NONE
 */
cose_kty_t edhoc_kty_from_suite(cipher_suite_t suite);

/*
 * @brief Get the COSE curve for signing from an EDHOC cipher suite
 *
 * @param[in]   suite   An EDHOC cipher suite
 *
 * @return  On success, a COSE curve used in the provided EDHOC cipher suite
 * @return  On failure, COSE_EC_NONE
 */
cose_curve_t edhoc_sign_curve_from_suite(cipher_suite_t suite);

/*
 * @brief Get the COSE hash algorithm from an EDHOC cipher suite
 *
 * @param[in]   suite   An EDHOC cipher suite
 *
 * @return  On success, a COSE hash algorithm used in the provided EDHOC cipher suite
 * @return  On failure, COSE_ALGO_NONE
 */
cose_algo_t edhoc_hash_from_suite(cipher_suite_t suite);

#endif /* EDHOC_CIPHER_SUITES_H */
