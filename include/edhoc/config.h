#ifndef EDHOC_CONFIG_H
#define EDHOC_CONFIG_H

/**
 * @def EDHOC_CIPHER_SUITE_X_ENABLED
 *
 * Enables support for a specific EDHOC cipher suite
 *
 */
#define EDHOC_CIPHER_SUITE_0_ENABLED
// #define EDHOC_CIPHER_SUITE_1_ENABLED
// #define EDHOC_CIPHER_SUITE_2_ENABLED
// #define EDHOC_CIPHER_SUITE_3_ENABLED


/**
 * @def EDHOC_AUTH_METHOD_X_ENABLED
 *
 * Enables support for a specific EDHOC authentication method
 *
 */
#define EDHOC_AUTH_METHOD_0_ENABLED
#define EDHOC_AUTH_METHOD_1_ENABLED
#define EDHOC_AUTH_METHOD_2_ENABLED
#define EDHOC_AUTH_METHOD_3_ENABLED


/**
 * @def EDHOC_ASYNC_API_ENABLED
 *
 * Exposes the individual EDHOC message functions for asynchronous usage.
 *
 */
#define EDHOC_ASYNC_API_ENABLED

/**
 * @def EDHOC_DEBUG_ENABLE
 *
 * Enables some extra methods that allow for easier testing and debugging
 *
 */
#define EDHOC_DEBUG_ENABLED

/**
 * @def EDHOC_AUTH_CERT_ENABLED
 *
 * Enables CBOR certificates as the EDHOC local credential
 *
 */

#define EDHOC_AUTH_CERT_ENABLED

#if defined(EDHOC_AUTH_CERT_ENABLED)
#define EDHOC_AUTH_CBOR_CERT
#define EDHOC_AUTH_DER_CERT
#endif

/**
 * @def EDHOC_AUTH_RPK_ENABLED
 *
 * Enables COSE raw public keys as the EDHOC local credential
 *
 */

#define EDHOC_AUTH_RPK_ENABLED

/**
 * @def EDHOC_COSE_HEADER_SIZE
 *
 * Sets the maximum number of COSE header elements
 */
#define EDHOC_COSE_HEADER_SIZE          (5)

/**
 * @def EDHOC_CREDENTIAL_MAX_SIZE
 *
 * Sets the maximum buffer size for credentials (raw keys or certificates)
 *
 */
#define EDHOC_CRED_SIZE           (256)

/**
 * @def EDHOC_CREDENTIAL_ID_MAX_SIZE
 *
 * Sets the maximum buffer size for credential identifiers
 *
 */
#define EDHOC_CRED_ID_SIZE        (256)

/**
 * @def EDHOC_ADD_DATA_MAX_SIZE
 *
 * Maximum number of additional data bytes to piggy-back on the EDHOC exchange
 *
 */
#define EDHOC_ADDITIONAL_DATA_SIZE             (64)


#include "check_config.h"

#endif /* EDHOC_CONFIG_H */
