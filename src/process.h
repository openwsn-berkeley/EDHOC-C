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
 * @param[in] id                Preferred cipher suite
 * @param[out] out              Output buffer to hold EDHOC message 1
 * @param[in] olen              Length of @p out
 *
 * @returns     On success the size of EDHOC message_1
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx,
                          corr_t correlation,
                          method_t method,
                          cipher_suite_id_t id,
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
 *
 * @param aeadInfo
 * @param th
 * @param prk
 * @param label
 * @param keyStreamLen
 * @param out
 * @param olen
 * @return
 */
int edhoc_compute_keystream2(const cose_aead_t *aeadInfo,
                             const uint8_t *th,
                             const uint8_t *prk,
                             const char *label,
                             size_t keyStreamLen,
                             uint8_t *out,
                             size_t olen);

/**
 *
 * @param aeadInfo
 * @param th
 * @param prk
 * @param label
 * @param out
 * @param olen
 * @return
 */
int edhoc_compute_K23mOrK3ae(const cose_aead_t *aeadInfo,
                             const uint8_t *th,
                             const uint8_t *prk,
                             const char *label,
                             uint8_t *out,
                             size_t olen);

/**
 *
 * @param aeadInfo
 * @param th
 * @param prk
 * @param label
 * @param out
 * @param olen
 * @return
 */
int edhoc_compute_IV23mOrIV3ae(const cose_aead_t *aeadInfo,
                               const uint8_t *th,
                               const uint8_t *prk,
                               const char *label,
                               uint8_t *out,
                               size_t olen);

/**
 *
 * @param sk
 * @param pk
 * @param prk_2e
 * @return
 */
int edhoc_compute_prk2e(const cose_key_t *sk, const cose_key_t *pk, uint8_t *prk_2e);

/**
 *
 * @param m
 * @param prk2e
 * @param sk
 * @param pk
 * @param prk3e2m
 * @return
 */
int edhoc_compute_prk3e2m(method_t m,
                          const uint8_t *prk2e,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk3e2m);

/**
 *
 * @param m
 * @param prk3e2m
 * @param sk
 * @param pk
 * @param prk4x3m
 * @return
 */
int edhoc_compute_prk4x3m(method_t m,
                          const uint8_t *prk3e2m,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk4x3m);

/**
 *
 * @param ctx
 * @param diagMsg
 * @param suitesR
 * @param suitesRLen
 * @param out
 * @param olen
 * @return
 */
ssize_t edhoc_create_error_msg(edhoc_ctx_t *ctx,
                               const char *diagMsg,
                               const uint8_t *suitesR,
                               size_t suitesRLen,
                               uint8_t *out,
                               size_t olen);


#endif /* EDHOC_PROCESSING_H */
