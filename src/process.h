#ifndef EDHOC_PROCESSING_H
#define EDHOC_PROCESSING_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "edhoc/edhoc.h"

#if !defined(EDHOC_ASYNC_API_ENABLED)

/**
 * @brief   Create EDHOC message 1
 *
 * @param[in] ctx               EDHOC context
 * @param[in] correlation       EDHOC correlation value
 * @param[in] method            EHDOC authentication method
 * @param[in] suite             Preferred cipher suite
 * @param[out] out              Output buffer to hold EDHOC message 1
 * @param[in] olen           Length of @p out
 *
 * @returns     On success the size of EDHOC message_1
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx,
                          corr_t correlation,
                          uint8_t method,
                          uint8_t suite,
                          uint8_t *out,
                          size_t olen);

/**
 * @brief   Create EDHOC message 2
 *
 * @param[in] ctx           EDHOC context
 * @param[in] msg1_buf      Buffer containing EDHOC message 1
 * @param[in] msg1_len      Length of EDHOC message 1
 * @param[in] ad2           Callback to fetch additional data (can be NULL)
 * @param[out] out          Output buffer to hold EDHOC message 1
 * @param[in] olen          Length of @p out
 *
 * @returns     On success size of EDHOC message 2
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx, const uint8_t *msg1_buf, size_t msg1_len, uint8_t *out, size_t olen);

/**
 * @brief   Create EDHOC message 3
 *
 * @param[in] ctx           EDHOC context
 * @param[in] msg2_buf      Buffer containing EDHOC message 2
 * @param[in] msg2_len      Length of @p msg2_buf
 * @param[in] ad2           Callback to fetch additional data (can be NULL)
 * @param[out] out          Output buffer to hold EDHOC message 3
 * @param[in] olen          Capacity of @p out
 *
 * @return  On success the size of EDHOC message 3
 * @return  On failure a negative value
 */
ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx, const uint8_t *msg2_buf, size_t msg2_len, uint8_t *out, size_t olen);

/**
 * @brief   Finalize the EDHOC ecxhange on the Initiator side
 *
 * @param[in,out] ctx       EDHOC context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
int edhoc_init_finalize(edhoc_ctx_t *ctx);

/**
 * @brief   Finalize the EDHOC ecxhange on the Responder side
 *
 * @param[in,out] ctx       EDHOC context
 * @param[in] msg3_buf      Buffer containing EDHOC message 3
 * @param[in] msg3_len      Length of @p msg3_buf
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
int edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *msg3_buf, size_t msg3_len);

#endif
/**
 * @brief Compute the EDHOC mac2 value
 *
 * @param ctx[in]   EDHOC context structure
 *
 * @return On success, returns EDHOC_SUCCESS
 * @return On failure a negative value (EDHOC_ERR_ILLEGAL_CIPHERSUITE, EDHOC_ERR_CRYPTO, ...)
 */
int edhoc_create_sig_or_mac23(edhoc_ctx_t *ctx,
                              const uint8_t *k_23m,
                              const uint8_t *iv_23m,
                              const uint8_t *th23,
                              ad_cb_t ad23,
                              uint8_t *out);

#endif /* EDHOC_PROCESSING_H */
