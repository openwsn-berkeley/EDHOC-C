#ifndef EDHOC_CONFIG_H
#define EDHOC_CONFIG_H

/**
 * @def EDHOC_CIPHER_SUITES
 *
 * Lists all the supported cipher suites for the EDHOC endpoints
 *
 * Used in:
 *      src/ciphersuites.c
 */
#define EDHOC_CIPHER_SUITES \
    EDHOC_CIPHER_SUITE_0

/**
 * \def EDHOC_AUTH_METHODS
 *
 * Lists all the supported cipher suites for the EDHOC endpoints
 *
 * Used in:
 *      src/ciphersuites.c
 */
#define EDHOC_AUTH_METHODS  \
    EDHOC_AUTH_SIGN_SIGN,   \
    EDHOC_AUTH_SIGN_STATIC, \
    EDHOC_AUTH_STATIC_SIGN, \
    EDHOC_AUTH_STATIC_STATIC

/**
 * @def EDHOC_DEBUG_ENABLE
 *
 * Enables some extra methods that allow for easier testing and debugging
 *
 */
#define EDHOC_DEBUG_ENABLE

/**
 * @def EDHOC_AUTH_CBOR_CERT
 *
 * Enable authentication with CBOR certificates
 *
 */
#define EDHOC_AUTH_CBOR_CERT

/**
 * @def EDHOC_AUTH_PUB_KEY
 *
 * Enable authentication with a raw COSE public key
 *
 */
// #define EDHOC_AUTH_PUB_KEY

/**
 * @def EDHOC_MAX_CREDENTIAL_SIZE
 *
 * Sets an upper-bound on the size of the credentials (either raw public key or CBOR certificate)
 *
 */
#define EDHOC_MAX_CRED_SIZE       150

#endif //EDHOC_CONFIG_H
