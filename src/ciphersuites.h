#ifndef EDHOC_CIPHER_SUITES_H
#define EDHOC_CIPHER_SUITES_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "edhoc/cose.h"
#include "edhoc/edhoc.h"

typedef struct cipher_suite_t cipher_suite_t;

struct cipher_suite_t{
    uint8_t id;
    const char* name;
    cose_algo_id_t aeadCipher;
    cose_algo_id_t hashAlgorithm;
    cose_curve_t dhCurve;
    cose_algo_id_t signAlgorithm;
    cose_curve_t signCurve;
    cose_algo_id_t appAeadCipher;
    cose_algo_id_t appHashAlgorithm;
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
 * @brief   Selects a cipher suite and verifies its availability
 *
 * @return Pointer to cipher suite on success
 * @return NULL on failure
 */
const cipher_suite_t *edhoc_cipher_suite_from_id(uint8_t cipher_suite);

#endif /* EDHOC_CIPHER_SUITES_H */
