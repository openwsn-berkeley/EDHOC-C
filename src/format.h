#ifndef EDHOC_FORMATTING_H
#define EDHOC_FORMATTING_H

#include <stdint.h>
#include <stddef.h>

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include "ciphersuites.h"

typedef struct edhoc_data2_t edhoc_data2_t;
typedef struct edhoc_data3_t edhoc_data3_t;

typedef struct edhoc_plaintext23_t edhoc_plaintext23_t;

typedef struct edhoc_msg1_t edhoc_msg1_t;
typedef struct edhoc_msg2_t edhoc_msg2_t;
typedef struct edhoc_msg3_t edhoc_msg3_t;
typedef struct edhoc_error_msg_t edhoc_error_msg_t;

typedef struct bstr_id_t bstr_id_t;

struct bstr_id_t {
    size_t length;
    union {
        int8_t integer;
        const uint8_t *bstr;
    };
};

/**
 * @brief EDHOC message 1 serialization/deserialization structures
 */

struct edhoc_msg1_t {
    uint8_t methodCorr;                     ///< Method correlation value
    const cipher_suite_t *cipherSuite;      ///< Selected cipher suites
    cose_key_t gX;                         ///< Ephemeral public key
    bstr_id_t cidi;                         ///< Initiator connection identifier
    const uint8_t *ad1;                     ///< Additional data
    size_t ad1Len;                         ///< Length of the additional data
};

/**
 * @brief EDHOC message 2 serialization/deserialization structures
 */

struct edhoc_data2_t {
    bstr_id_t cidi;
    cose_key_t gY;
    bstr_id_t cidr;
};

struct edhoc_plaintext23_t {
    cred_id_t *credId;
    const uint8_t *sigOrMac23;
    size_t sigOrMac23Len;
    const uint8_t *ad23;
    size_t ad23Len;
};

struct edhoc_msg2_t {
    edhoc_data2_t data2;
    const uint8_t *ciphertext2;
    size_t ciphertext2Len;
};

/**
 * @brief EDHOC message 3 serialization/deserialization structure
 */

struct edhoc_data3_t {
    bstr_id_t cidr;
};

struct edhoc_msg3_t {
    edhoc_data3_t data3;
    const uint8_t *ciphertext3;
    size_t ciphertext3Len;
};

/**
 * Brief EDHOC error message serialization/deserialization structure
 */

struct edhoc_error_msg_t {
    bstr_id_t cid;
    const char *diagnosticMsg;
    const uint8_t *suitesR;
    size_t suitesRLen;
};

/**
 *
 * @param msg1
 */
void format_msg1_init(edhoc_msg1_t *msg1);

/**
 *
 * @param msg2
 */
void format_msg2_init(edhoc_msg2_t *msg2);

/**
 *
 * @param msg3
 */
void format_msg3_init(edhoc_msg3_t *msg3);

/**
 *
 * @param errMsg
 */
void format_error_msg_init(edhoc_error_msg_t *errMsg);

/**
 *
 * @param plaintext
 */
void format_plaintext23_init(edhoc_plaintext23_t *plaintext);

/**
 * @brief Message encoding routine for EDHOC message_1
 *
 * @param[in] msg1  Pointer to a populated EDHOC message 1 structure
 * @param[out] out  Output buffer for the CBOR encoded EDHOC message_1
 * @param[in] olen  Maximum capacity of @p out
 *
 * @return On success the size of the EDHOC message_1
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING)
 */
ssize_t format_msg1_encode(const edhoc_msg1_t *msg1, uint8_t *out, size_t olen);

/**
 * @brief Message decoding routine for EDHOC message_1
 *
 * @param[in,out] msg1  Pointer to EDHOC msg1 structure to populate
 * @param[in] in  Buffer containing the EDHOC message_1
 * @param[in] ilen  Length of @p msg1
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_DECODING)
 */
int format_msg1_decode(edhoc_msg1_t *msg1, const uint8_t *in, size_t ilen);

/**
 * @brief Message encoding routine for EDHOC message_2
 *
 * @param[in,out] msg2      Pointer to EDHOC message 2 structure to populate
 * @param[in] corr          EDHOC correlation value
 * @param[out] out          Output buffer for the CBOR encoded EDHOC message_2
 * @param[in] olen          Maximum capacity of @p out
 *
 * @return On success returns the size of the EDHOC message_2
 * @return On failure returns a negative value (EDHOC_ERR_CBOR_ENCODING)
 */
ssize_t format_msg2_encode(const edhoc_msg2_t *msg2, corr_t corr, uint8_t *out, size_t olen);

/**
 * @brief Decoding routine for EDHOC message_2
 *
 * @param[in] ctx       Pointer to EDHOC message 2 structure
 * @param[in] corr      EDHOC correlation value
 * @param[in] suite     Selected cipher suite
 * @param[in] msg2      Buffer containing the EDHOC message_2
 * @param[in] msg2Len  Length of @p msg2
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_DECODING, EDHOC_ERR_BUFFER_OVERFLOW,
 * EDHOC_ERR_ILLEGAL_CIPHERSUITE, ..)
 */
int format_msg2_decode(edhoc_msg2_t *msg2,
                       corr_t corr,
                       const cipher_suite_t *suite,
                       const uint8_t *msg2Buf,
                       size_t msg2Len);

/**
 * @brief Message encoding routine for EDHOC message_3
 *
 * @param[in] msg3
 * @param[out] out          Output buffer for the CBOR encoded EDHOC message_3
 * @param[in] olen          Maximum capacity of @p out
 *
 * @return On success returns the size of the EDHOC message_3
 * @return On failure returns a negative value (EDHOC_ERR_CBOR_ENCODING)
 */
ssize_t format_msg3_encode(const edhoc_msg3_t *msg3, corr_t corr, uint8_t *out, size_t olen);

/**
 * @brief Decoding routine for EDHOC message 3
 *
 * @param[in,out] ctx   Pointer to the EDHOC context structure
 * @param[in] msg3      Buffer containing the EDHOC message 3
 * @param[in] msg3_len  Length of @p msg3
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative return code (EDHOC_ERR_CBOR_ENCODING)
 */
int format_msg3_decode(edhoc_msg3_t *msg3, corr_t corr, const uint8_t *msg3_buf, size_t msg3_len);

/**
 * @brief Encoding routine for the EDHOC data_2 structure
 *
 * @param[in] data2     Pointer to an EDHOC data2 structure
 * @param[in] corr      Correlation value
 * @param[out] out      Output buffer
 * @param[in] olen      Maximum length of @p out
 *
 * @return On success the size of data_2 message part
 * @return On failure a negative value (EDHOC_ERR_CBOR_ENCODING, ..)
 */
ssize_t format_data2_encode(const edhoc_data2_t *data2, corr_t corr, uint8_t *out, size_t olen);

/**
 * @brief Encoding routine for the EDHOC data_3 structure
 *
 * @param[in] corr         EDHOC correlation value
 * @param[in] cidr         Connection identifier of the responder
 * @param[in] cidr_len     Length @p cidr
 * @param[out] out         Output buffer for the CBOR encoded EDHOC message_3
 * @param[in] olen         Maximum capacity if @p out
 *
 * @return On success returns the size of the EDHOC message_3
 * @return On failure returns a negative value (e.g. EDHOC_CBOR_ERR_ENCODING)
 */
ssize_t format_data3_encode(const edhoc_data3_t *data3, corr_t corr, uint8_t *out, size_t olen);

/**
 * @brief Encoding routine for the EDHOC-KDF info structure
 *
 * @param[in] id        COSE algorithm identifier
 * @param[in] th        Transcript hash
 * @param[in] label     String label
 * @param[in] len       The length of the KDF output
 * @param[out] out      Output buffer
 * @param[in] olen      The maximum capacity of @p out
 *
 * @returns  On success, length of the final CBOR encode info byte string
 * @returns  On failure, EDHOC_ERR_CBOR_ENCODING or another negative value
 **/
ssize_t
format_info_encode(cose_algo_id_t id, const uint8_t *th, const char *label, size_t len, uint8_t *out, size_t olen);

/**
 * @brief Encoding routine for the external data of the inner COSE Encrypt0 message.
 *
 * @param th
 * @param credCtx
 * @param credType
 * @param ad2
 * @return
 */
ssize_t format_external_data_encode(const uint8_t *th,
                                    cred_t credCtx,
                                    cred_type_t credType,
                                    ad_cb_t ad2,
                                    uint8_t *out,
                                    size_t olen);

/**
 *
 * @param plaintext
 * @param out
 * @param olen
 * @return
 */
ssize_t format_plaintext23_encode(const edhoc_plaintext23_t *plaintext, uint8_t *out, size_t olen);

/**
 *
 * @param plaintext
 * @param in
 * @param ilen
 * @return
 */
int format_plaintext23_decode(edhoc_plaintext23_t *plaintext, int8_t *bstr_id, uint8_t *in, size_t ilen);

/**
 *
 * @param errMsg
 * @param out
 * @param olen
 * @return
 */
ssize_t format_error_msg_encode(const edhoc_error_msg_t *errMsg, uint8_t *out, size_t olen);


#endif /* EDHOC_FORMATTING_H */
