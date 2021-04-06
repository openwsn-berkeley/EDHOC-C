#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

#include <stdbool.h>

#include "edhoc/cose.h"

/**
 * @ brief C509 certificate types
 */
typedef enum c509_type {
    C509_NATIVE = 0,
    C509_ENCODED = 1
} c509_type_t;

/**
 * @brief EDHOC credential types
 */
typedef enum cred_type {
    CRED_TYPE_CBOR_CERT = 0,
    CRED_TYPE_DER_CERT = 1,
    CRED_TYPE_RPK = 2,
} cred_type_t;

typedef struct c509_buf c509_buf_t;
typedef struct rpk_buf rpk_buf_t;

struct c509_buf {
    cose_hdr_param_t param;
    const uint8_t *p;
    size_t length;
};

struct rpk_buf {
    const uint8_t *p;
    size_t length;
};

struct rpk_t {
    const char *subjectName;
    cose_key_t coseKey;
    rpk_buf_t raw;
};

typedef struct c509_t c509_t;
typedef struct rpk_t rpk_t;
typedef struct cred_id_t cred_id_t;

struct c509_t {
    c509_buf_t raw;
    c509_buf_t tbs;
    c509_type_t cborCertificateType;
    c509_buf_t serialNumber;
    c509_buf_t issuer;
    size_t validityNotBefore;
    size_t validityNotAfter;
    c509_buf_t subject;
    int32_t subjectPublicKeyAlgorithm;
    c509_buf_t subjectPublicKey;
    c509_buf_t extensions;
    int32_t issuerSignatureAlgorithm;
    c509_buf_t issuerSignatureValue;
};

struct cred_id_t {
    const uint8_t *p;
    size_t length;
    cose_header_t map[EDHOC_COSE_HEADER_SIZE];
};

#if defined(EDHOC_AUTH_CERT_ENABLED)
#if defined(EDHOC_AUTH_CBOR_CERT)

/**
 * @brief Initialize a c509 certificate context.
 *
 * @param[in,out] c509Ctx
 */
void cred_c509_init(c509_t *c509Ctx);

#endif

#if defined(EDHOC_AUTH_DER_CERT)

/**
 * @brief Initialize a x509 certificate context.
 *
 * @param[in,out] x509Ctx
 */
void cred_x509_init(void *x509Ctx);

#endif
#endif

#if defined(EDHOC_AUTH_RPK_ENABLED)

/**
 * @brief Initialize a raw public key (rpk) context.
 *
 * @param[in,out] rpkCtx
 */
void cred_rpk_init(rpk_t *rpkCtx);

#endif

/**
 * @brief Initialize a credential identifier (COSE header map) context
 *
 * @param[in,out] credIdCtx
 */
void cred_id_init(cred_id_t *credIdCtx);

#if defined(EDHOC_AUTH_CERT_ENABLED)
#if defined(EDHOC_AUTH_DER_CERT)

/**
 * @brief Parse a DER-encoded certificate.
 *
 * @param[in,out] x509Ctx   An x509 certificate context to populate
 * @param[in] in            Input buffer containing the DER-encoded certificate
 * @param[in] ilen          Length of @p in
 *
 * @return On success returns EDHOC_SUCCESS
 */
int cred_x509_from_der(void *x509Ctx, const uint8_t *in, size_t ilen);

#endif

#if defined(EDHOC_AUTH_CBOR_CERT)

/**
 * @brief Parse a C509-encoded certificate.
 *
 * @param[in,out] c509Ctx   An x509 certificate context to populate
 * @param[in] in            Input buffer containing the C509 certificate
 * @param[in] ilen          Length of @p in
 *
 * @return On success returns EDHOC_SUCCESS
 */
int cred_c509_from_cbor(c509_t *c509Ctx, const uint8_t *in, size_t ilen);

#endif
#endif


#if defined(EDHOC_AUTH_RPK_ENABLED)

/**
 * @brief Parse a RPK (COSE key)
 *
 * @param[in,out] rpkCtx
 * @param[in] in
 * @param[in] ilen
 *
 * @return On success returns EDHOC_SUCCESS
 */
int cred_rpk_from_cbor(rpk_t *rpkCtx, const uint8_t *in, size_t ilen);

#endif

/**
 *
 * @param credIdCtx
 * @param in
 * @param ilen
 * @return
 */
int cred_id_from_cbor(cred_id_t *credIdCtx, const uint8_t *in, size_t ilen);

#endif /* EDHOC_CREDENTIALS_H */
