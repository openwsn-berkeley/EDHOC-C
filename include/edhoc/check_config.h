#ifndef EDHOC_CHECK_CONFIG_H
#define EDHOC_CHECK_CONFIG_H

#if !defined(EDHOC_AUTH_CERT_ENABLED) && !defined(EDHOC_AUTH_RPK_ENABLED)
#error "There needs to be at least one credential type enabled."
#endif

#if !defined(EDHOC_CIPHER_SUITE_0_ENABLED) && \
    !defined(EDHOC_CIPHER_SUITE_1_ENABLED) && \
    !defined(EDHOC_CIPHER_SUITE_2_ENABLED) && \
    !defined(EDHOC_CIPHER_SUITE_3_ENABLED)
#error "No cipher suites supported."
#endif

#if !defined(EDHOC_AUTH_METHOD_0_ENABLED) && \
    !defined(EDHOC_AUTH_METHOD_1_ENABLED) && \
    !defined(EDHOC_AUTH_METHOD_2_ENABLED) && \
    !defined(EDHOC_AUTH_METHOD_3_ENABLED)
#error "No authentication methods supported."
#endif

#if defined(EDHOC_AUTH_CERT_ENABLED) && (!defined(EDHOC_AUTH_CBOR_CERT) && !defined(EDHOC_AUTH_DER_CERT))
#error "At least one certificate type should be enabled when EDHOC_AUTH_CERT_ENABLED is true"
#endif

#if !defined(EDHOC_AUTH_CERT_ENABLED) && (defined(EDHOC_AUTH_CBOR_CERT) || defined(EDHOC_AUTH_DER_CERT))
#error "Certificate-based authentication must be supported for EDHOC_AUTH_CBOR_CERT or EDHOC_AUTH_DER_CERT"
#endif

#endif /* EDHOC_CHECK_CONFIG_H */
