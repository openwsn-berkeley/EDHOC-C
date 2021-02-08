#ifndef EDHOC_PROCESSING_H
#define EDHOC_PROCESSING_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "edhoc/edhoc.h"

#define ENCRYPT0                                     (9)
#define SIGNATURE1                                   (11)

#define EDHOC_A23M_MAX_SIZE                          (CBOR_ARRAY_LE23_FMT_SIZE +                                     \
                                                      CBOR_STR_LE23_FMT_SIZE + ENCRYPT0 +                            \
                                                      CBOR_CREDENTIAL_ID_FMT_SIZE + EDHOC_CREDENTIAL_ID_MAX_SIZE +   \
                                                      CBOR_BYTES_LE65536_FMT_SIZE + EDHOC_HASH_MAX_SIZE +            \
                                                      EDHOC_CREDENTIAL_MAX_SIZE)


#if (EDHOC_A23M_MAX_SIZE <= 23)
#define CBOR_A23_FMT_SIZE                           (CBOR_BYTES_LE23_FMT_SIZE)
#elif (EDHOC_A23M_MAX_SIZE > 23 && EDHOC_A23M_MAX_SIZE < 256)
#define CBOR_A23_FMT_SIZE                           (CBOR_BYTES_LE256_FMT_SIZE)
#elif (EDHOC_A23M_MAX_SIZE >= 256 && EDHOC_A23M_MAX_SIZE < 65536)
#define CBOR_A23M_FMT_SIZE                           (CBOR_BYTES_LE65536_FMT_SIZE)
#else
#define CBOR_A23_FMT_SIZE                           (9)
#endif

#define EDHOC_M23_MAX_SIZE                          (CBOR_ARRAY_LE23_FMT_SIZE +                                     \
                                                     CBOR_STR_LE23_FMT_SIZE + SIGNATURE1 +                          \
                                                     CBOR_CREDENTIAL_ID_FMT_SIZE + EDHOC_CREDENTIAL_ID_MAX_SIZE +   \
                                                     CBOR_A23M_FMT_SIZE + EDHOC_A23M_MAX_SIZE +                     \
                                                     CBOR_BYTES_LE23_FMT_SIZE + EDHOC_AUTH_TAG_MAX_SIZE)

#define EDHOC_MAX_A3AE_LEN                          (CBOR_ARRAY_LE23_FMT_SIZE +                                     \
                                                     CBOR_STR_LE23_FMT_SIZE + SIGNATURE1 +                          \
                                                     CBOR_BYTES_LE23_FMT_SIZE +                                     \
                                                     CBOR_BYTES_LE256_FMT_SIZE + EDHOC_HASH_MAX_SIZE)

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
 * @ Create transcript hash 2 (TH_2) from EDHOC message_1 and EDHOC data_2
 *
 * @param[in] msg1          EDHOC messsage_1
 * @param[in] msg1_len      Length of @p msg1
 * @param[in] data_2        EDHOC data_2 structure
 * @param[in] data2_len     Length of @p data_2
 * @param[out] th2          Output buffer, must be at least of size EDHOC_TH_MAX_SIZE
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns an error code (<0), i.e., EDHOC_ERR_CRYPTO, ...
 */
int edhoc_compute_th2(const uint8_t *msg1, size_t msg1_len, const uint8_t *data_2, size_t data2_len, uint8_t *th2);

/**
 *
 * @param th2
 * @param ciphertext_2
 * @param ct2_len
 * @param data3
 * @param data3_len
 * @param th3
 * @return
 */
int edhoc_compute_th3(const uint8_t *th2,
                      const uint8_t *ciphertext_2,
                      size_t ct2_len,
                      const uint8_t *data3,
                      size_t data3_len,
                      uint8_t *th3);

/**
 *
 * @param th3
 * @param ciphertext_3
 * @param ct3_len
 * @param th4
 * @return
 */
int edhoc_compute_th4(const uint8_t *th3, const uint8_t *ciphertext_3, size_t ct3_len, uint8_t *th4);

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
 * @param prk_2e
 * @param sk
 * @param pk
 * @param prk_3e2m
 * @return
 */
int edhoc_compute_prk3e2m(method_t m,
                          const uint8_t *prk_2e,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk_3e2m);

/**
 *
 * @param m
 * @param prk_3e2m
 * @param sk
 * @param pk
 * @param prk_4x3m
 * @return
 */
int edhoc_compute_prk4x3m(method_t m,
                          const uint8_t *prk_3e2m,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk_4x3m);

/**
 *
 * @param aead
 * @param k_23m
 * @param iv_23m
 * @param th23
 * @param out
 * @return
 */
ssize_t edhoc_compute_mac23(cose_algo_t aead,
                            cred_container_t *local_cred,
                            const uint8_t *k_23m,
                            const uint8_t *iv_23m,
                            const uint8_t *th23,
                            uint8_t *out);

/**
 *
 * @param role
 * @param m
 * @param sign_crv
 * @param local_cred
 * @param tag
 * @param tag_len
 * @param th23
 * @param ad23
 * @param out
 * @return
 */
ssize_t edhoc_compute_sig23(edhoc_role_t role,
                            method_t m,
                            cred_container_t *local_cred,
                            const uint8_t *tag,
                            size_t tag_len,
                            const uint8_t *th23,
                            ad_cb_t ad23,
                            uint8_t *out);

#endif /* EDHOC_PROCESSING_H */
