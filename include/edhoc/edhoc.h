#ifndef EDHOC_EDHOC_H
#define EDHOC_EDHOC_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>


typedef enum cipher_suite {
    EDHOC_CIPHER_SUITE_0,
    EDHOC_CIPHER_SUITE_1,
    EDHOC_CIPHER_SUITE_2,
    EDHOC_CIPHER_SUITE_3
} cipher_suite_t;

typedef struct EDHOC_Msg1 {
    uint8_t method_corr;
    cipher_suite_t *suites;
    size_t s_size;
    uint8_t *g_x;
    size_t g_x_size;
    uint8_t *connection_idi;
    size_t ci_size;
    uint8_t *additional_data_1;
    size_t ad1_size;
} EDHOC_Msg1;


bool EDHOC_Msg1_Decode(const uint8_t *msg, size_t mSize, EDHOC_Msg1 *message);

/**
 *
 * @brief               Create a EDHOC message1. Should be called by the EDHOC Initiator.
 *
 * @param msg[in,out]
 * @param method_corr[in]
 * @param s[in]
 * @param s_len[in]
 * @param selected[in]
 * @param g_x[in]
 * @param g_x_len[in]
 * @param cid[in]
 * @param cid_len[in]
 * @param aad1[in]
 * @param aad1_len[in]
 *
 * @returns             size of the EDHOC message1 on success
 * @returns             <0 on error
 */
ssize_t EDHOC_Build_Msg1(EDHOC_Msg1 *msg, uint8_t method_corr, cipher_suite_t *s, uint8_t s_len, uint8_t selected,
                         uint8_t *g_x, int16_t g_x_len, uint8_t *cid, uint8_t cid_len, uint8_t *aad1, uint8_t aad1_len);

#endif /* EDHOC_EDHOC_H */
