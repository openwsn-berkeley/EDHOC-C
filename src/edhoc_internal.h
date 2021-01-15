#ifndef EDHOC_EDHOC_INTERNAL_H
#define EDHOC_EDHOC_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#include "edhoc/edhoc.h"

/**
 * @brief Build and CBOR encode the EDHOC message 1
 *
 * @param corr[in]      EDHOC correlation value
 * @param method[in]    EDHOC authentication method
 * @param suite[in]     EDHOC selected cipher suite
 * @param key[in]       Pointer to ephemeral COSE key (message includes only the public part)
 * @param cidi[in]      Pointer to connection identifier (Initiator)
 * @param cidi_len[in]  Length of @p cidi
 * @param ad1[in]       Pointer to additional data
 * @param ad1_len[in]   Length of @p ad1
 * @param out[out]      Output buffer for the message
 * @param olen[in]      Maximum length of @p out
 *
 * @return On success the size of the EDHOC message 1
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING)
 */
ssize_t edhoc_msg1_encode(corr_t corr,
                          method_t method,
                          cipher_suite_t suite,
                          cose_key_t *key,
                          const uint8_t *cidi,
                          size_t cidi_len,
                          const uint8_t *ad1,
                          size_t ad1_len,
                          uint8_t *out,
                          size_t olen);

/**
 * @brief Decoding routine for EDHOC message 1
 *
 * @param ctx[in]   Pointer to EDHOC context structure
 * @param in[in]    Pointer to buffer containing the EDHOC message 1
 * @param ilen[in]  Length of @p ilen
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_DECODING, EDHOC_ERR_BUFFER_OVERFLOW,
 * EDHOC_ERR_ILLEGAL_CIPHERSUITE, ..)
 */
int edhoc_msg1_decode(edhoc_ctx_t *ctx, const uint8_t *in, size_t ilen);


/**
 * @brief Create the EDHOC data_2 message part for EDHOC message 2
 *
 * @param corr[in]      EDHOC correlation value.
 * @param cidi[in]      Pointer to the Initiator's connection identifier.
 * @param cidi_len[in]  Length of @p cidi
 * @param cidr[in]      Pointer to the Responder's connection identifier.
 * @param cidr_len[in]  Length of @p cidr
 * @param eph_key[in]   Pointer to Responder's ephemeral key
 * @param out[out]      Output buffer
 * @param olen[in]      Maximum length of @p out
 *
 * @return On success the size of data_2 message part
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING, ..)
 */
ssize_t edhoc_data2_encode(corr_t corr,
                           const uint8_t *cidi,
                           size_t cidi_len,
                           const uint8_t *cidr,
                           size_t cidr_len,
                           const cose_key_t *eph_key,
                           uint8_t *out,
                           size_t olen);

/**
 * @brief Creates a CBOR encoded info structure
 *
 * @param[in] id        COSE algorithm identifier
 * @param[in] th        Transcript hash
 * @param[in] label     String label
 * @param[in] len       The length of the KDF output
 * @param[out] out      Output buffer
 * @param[out] olen     The maximum size of @p out
 *
 * @returns  On success, length of the final CBOR encode info byte string
 * @returns  On failure, EDHOC_ERR_CBOR_ENCODING or another negative value
 **/
ssize_t edhoc_info_encode(cose_algo_t id, const uint8_t *th, const char *label, size_t len, uint8_t *out, size_t olen);


#endif /* EDHOC_EDHOC_INTERNAL_H */
