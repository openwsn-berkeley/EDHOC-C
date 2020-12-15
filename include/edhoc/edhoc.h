#ifndef EDHOC_EDHOC_H
#define EDHOC_EDHOC_H

#include <stdint.h>
#include <stdio.h>

typedef enum cipher_suite {
    EDHOC_CIPHER_SUITE_0,
    EDHOC_CIPHER_SUITE_1,
    EDHOC_CIPHER_SUITE_2,
    EDHOC_CIPHER_SUITE_3
} cipher_suite_t;

typedef enum auth_method {
    SIGN_SIGN,
    SIGN_STATIC,
    STATIC_SIGN,
    STATIC_STATIC
} method_t;

typedef enum msg_correlation {
    NO_CORR,
    CORR_1_2,
    CORR_2_3,
    CORR_ALL
} corr_t;

typedef struct EDHOC_Msg1 {
    uint8_t method_corr;
    const uint8_t *suites;
    size_t s_size;
    uint8_t selected;
    const uint8_t *g_x;
    size_t g_x_size;
    uint8_t *connection_idi;
    size_t ci_size;
    const uint8_t *additional_data_1;
    size_t ad1_size;
} EDHOC_Msg1_t;

typedef struct EDHOC_Msg2 {
    uint8_t *data_2;
    size_t d_size;
    uint8_t *ciphertext_2;
    size_t c_size;
} EDHOC_Msg2_t;

typedef struct EDHOC_ctx {
    EDHOC_Msg1_t message_1;
    EDHOC_Msg2_t message_2;
} EDHOC_ctx_t;


/**
 * @brief   Parse an EDHOC message 1
 * @param[out]  ctx        EDHOC context struct to populate
 * @param[in]   buf        pointer to a raw EDHOC message 1
 * @param[in]   bsize      length of the EDHOC message at @p buf
 *
 * @returns     0 on success
 * @returns     <0 on error
 */

int8_t EDHOC_Msg1_Decode(EDHOC_ctx_t *ctx, const uint8_t *buf, size_t bsize);

/**
 * @brief   Parse an EDHOC message 2
 * @param[out]  ctx        EDHOC context struct to populate
 * @param[in]   buf        pointer to a raw EDHOC message 2
 * @param[in]   bsize      length of the EDHOC message at @p buf
 *
 * @returns     0 on success
 * @returns     <0 on error
 */

int8_t EDHOC_Msg2_Decode(EDHOC_ctx_t *ctx, const uint8_t *buf, size_t bsize);

/**
 *
 * @brief   Initializes a EDHOC message 1 struct, to build an encoded EDHOC message 1.
 *
 * @param ctx[out]          initializes the EDHOC context struct
 * @param correlation       correlation value for the EDHOC exchange
 * @param method            EDHOC authentication method
 * @param s[in]             cipher suite list to convey to the responder, first element is the selected cipher suite
 * @param s_len[in]         length of @p s
 * @param g_x[in]           ephemeral public key
 * @param g_x_len[in]       length of @p g_x
 * @param cid[in]           initiator connection identifier
 * @param cid_len[in]       length of @p cid
 * @param aad1[in]          additional data to send to the responder
 * @param aad1_len[in]      length of @p aad1
 *
 * @returns     0 on success
 * @returns     <0 on error
 */
int8_t EDHOC_Msg1_Build(EDHOC_ctx_t *ctx, corr_t correlation, method_t method, const uint8_t *s, size_t s_len,
                        const uint8_t *g_x, size_t g_x_len, const uint8_t *cid, size_t cid_len, const uint8_t *aad1,
                        size_t aad1_len);

/**
 *
 * @brief   Initializes a EDHOC message 2 struct, to build an encoded EDHOC message 2.
 *
 * @param ctx[out]          initializes the EDHOC context struct
 * @param data_2[in]        CBOR encoded data_2 struct
 * @param d_size            size of the CBOR sequence at @p data_2
 * @param ciphertext_2      ciphertext byte string
 * @param c_size            length of @p ciphertext_2
 *
 * @returns     0 on success
 * @returns     <0 on error
 */
int8_t EDHOC_Msg2_Build(EDHOC_ctx_t *ctx);

/**
 *
 * @brief   Builds a CBOR-encoded EDHOC message 1
 *
 * @param ctx[in]       initialized EDHOC context struct
 * @param buffer[out]   buffer holding the encoded message
 * @param bsize[in]     total size of the buffer which will hold the encoded message
 *
 * @returns     size of the message 1 on success
 * @returns     <0 on error
 */
ssize_t EDHOC_Msg1_Encode(const EDHOC_ctx_t *ctx, uint8_t *buffer, size_t bsize);

#endif /* EDHOC_EDHOC_H */
