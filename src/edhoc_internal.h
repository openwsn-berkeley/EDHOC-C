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
                          ad_cb_t ad1,
                          uint8_t *out,
                          size_t olen);

/**
 * @brief Decoding routine for EDHOC message 1
 *
 * @param ctx[in]   Pointer to EDHOC context structure
 * @param msg1[in]    Pointer to buffer containing the EDHOC message 1
 * @param msg1_len[in]  Length of @p msg
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_DECODING, EDHOC_ERR_BUFFER_OVERFLOW,
 * EDHOC_ERR_ILLEGAL_CIPHERSUITE, ..)
 */
int edhoc_msg1_decode(edhoc_ctx_t *ctx, const uint8_t *msg1, size_t msg1_len);


/**
 * @brief Decoding routine for EDHOC message 2
 *
 * @param ctx[in]   Pointer to EDHOC context structure
 * @param msg2[in]    Pointer to buffer containing the EDHOC message 2
 * @param msg2_len[in]  Length of @p msg2
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_DECODING, EDHOC_ERR_BUFFER_OVERFLOW,
 * EDHOC_ERR_ILLEGAL_CIPHERSUITE, ..)
 */
int edhoc_msg2_decode(edhoc_ctx_t *ctx, const uint8_t *msg2, size_t msg2_len);


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

/**
 * @brief Creates the external additional data for a COSE message.
 *
 * @param[in] th        Transcript hash
 * @param[in] cred      Public credentials (CBOR certificate or public key)
 * @param[in] cred_len  Length of @p cred
 * @param[out] out      Output buffer
 * @param[in] olen      Maximum length of @p out
 *
 * @return On success the size of the external data
 * @return On failure a negative error code (EDHOC_ERR_CBOR_ENCODING, ..)
 */
ssize_t cose_ext_aad_encode(const uint8_t *th,
                            const uint8_t *cred,
                            size_t cred_len,
                            ad_cb_t ad2,
                            uint8_t *out,
                            size_t olen);

/**
 * @brief Create the Enc structure for the COSE Encrypt0 message
 *
 * @param[in] cred_id           Pointer to the credential identifier
 * @param[in] cred_id_len       Length of @p cred_id
 * @param[in] external_aad      Pointer to the external additional data for the COSE Encrypt0 message
 * @param[in] external_aad_len  Length of @p external_aad
 * @param[out] out              Buffer to store the CBOR encoded Enc structure
 * @param[in] olen              Maximum length of @p out
 *
 * @return On success the size of the CBOR encoded Enc structure
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING, ...)
 */
ssize_t cose_enc_structure_encode(const uint8_t *cred_id,
                                  size_t cred_id_len,
                                  const uint8_t *external_aad,
                                  size_t external_aad_len,
                                  uint8_t *out,
                                  size_t olen);

/**
 * @brief CBOR encode EDHOC message 2
 * @param[in] data2
 * @param[in] data2_len
 * @param[in] ct2
 * @param[in] ct2_len
 * @param[out] out
 * @param[in] olen
 *
 * @return
 */
ssize_t edhoc_msg2_encode(const uint8_t* data2,
                          size_t data2_len,
                          const uint8_t* ct2,
                          size_t ct2_len,
                          uint8_t* out,
                          size_t olen);
/**
 * @brief CBOR encode EDHOC message 3
 * @param[in] data3
 * @param[in] data3_len
 * @param[in] ct3
 * @param[in] ct3_len
 * @param[out] out
 * @param[in] olen
 *
 * @return
 */
ssize_t edhoc_msg3_encode(const uint8_t* data3,
                          size_t data3_len,
                          const uint8_t* ct3,
                          size_t ct3_len,
                          uint8_t* out,
                          size_t olen);

/**
 * @brief Decodes P_2e and verifies the included signature
 *
 * @param[in] p2e       Plaintext included in EDHOC message 2
 * @param[in] p2e_len   Length of @p p2e
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value (i.e., EDHOC_ERR_CRYPTO, EDHOC_ERR_CBOR_DECODING, ...)
 */
int edhoc_p2e_decode(uint8_t* p2e, size_t p2e_len);

/**
 * @brief Encode the EDHOC data 3 structure
 *
 * @param[in] corr         EDHOC correlation value
 * @param[in] cidr         Connection identifier of the responder
 * @param[in] cidr_len     Length @p cidr
 * @param[out] out
 * @param[in] olen
 * @return
 */
ssize_t edhoc_data3_encode(corr_t corr, const uint8_t *cidr, size_t cidr_len, uint8_t *out, size_t olen);

#endif /* EDHOC_EDHOC_INTERNAL_H */
