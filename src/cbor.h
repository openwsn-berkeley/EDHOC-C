#ifndef EDHOC_CBOR_H
#define EDHOC_CBOR_H

#include <stdint.h>
#include <stdbool.h>

#include "edhoc/edhoc.h"

#define CBOR_SUCCESS    (0)
#define CBOR_FAILED     (-1)

#define CBOR_UINT                   (0x00)
#define CBOR_NINT                   (0x01)
#define CBOR_BSTR                   (0x02)
#define CBOR_TSTR                   (0x03)
#define CBOR_ARRAY                  (0x04)
#define CBOR_MAP                    (0x05)
#define CBOR_TAG                    (0x06)
#define CBOR_FLOAT                  (0x07)
#define CBOR_INVALID                (0x08)

#define CBOR_DEC_CHECK_RET(enc)        \
if ((enc) != CBOR_SUCCESS) {           \
    ret = EDHOC_ERR_CBOR_DECODING;     \
    goto exit;                         \
}

#define CBOR_ENC_CHECK_RET(enc)        \
if ((enc) != CBOR_SUCCESS) {           \
    ret = EDHOC_ERR_CBOR_ENCODING;     \
    goto exit;                         \
}

/**
 * @brief Set up a CBOR decoder context.
 *
 * @param[in] decoder   Decoder context to initialize
 * @param[in] buffer    Buffer holding CBOR-encoded data
 * @param[in] len       Length of @p buffer
 */
void cbor_init_decoder(void *decoder, const uint8_t *buffer, size_t len);

/**
 * @brief Retrieve a CBOR byte string from a buffer.
 *
 * @param[in] decoder   Decoder context
 * @param[out] buffer   Pointer to the decoded byte string
 * @param[out] len      Length of the decoded byte string
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED
 */
int8_t cbor_get_bstr(void *decoder, const uint8_t **buffer, size_t *len);

/**
 * @brief Retrieve a CBOR uint8 from a buffer.
 *
 * @param[in] decoder   Decoder context
 * @param[out] value    Pointer to the decoded value
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED
 */
int8_t cbor_get_uint8_t(void *decoder, uint8_t *value);

/**
 * @brief Retrieve a CBOR int8 from a buffer.
 *
 * @param[in] decoder   Decoder context
 * @param[out] value    Pointer to the decoded value
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED
 */
int8_t cbor_get_int8_t(void *decoder, int8_t *value);

/**
 * @brief Retrieve a CBOR int32 from a buffer.
 *
 * @param[in] decoder   Decoder context
 * @param[out] value    Pointer to the decoded value
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED
 */
int8_t cbor_get_int32_t(void *decoder, int32_t *value);

/**
 * @brief Retrieve the type of the next CBOR element in the buffer.
 *
 * @param[in] decoder   Decoder context
 *
 * @return Returns a CBOR type on success else CBOR_FAIL
 */
int8_t cbor_get_type(void *decoder);

/**
 * @brief Check if the current CBOR buffer is exhausted
 *
 * @param[in] decoder   Decoder context
 *
 * @return Returns true if exhausted else false
 */
bool cbor_at_end(void *decoder);

/**
 *
 * @param decoder
 * @param tstr
 * @param len
 * @return
 */
int8_t cbor_get_tstr(void *decoder, const uint8_t **tstr, size_t *len);

/**
 * @brief Get a integer value from the CBOR map through an integer key
 *
 * @param[in] decoder
 * @param[in] key
 * @param[out] value
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_map_from_int_int(void *decoder, int8_t key, int8_t *value);

/**
 *
 * @param decoder
 * @param key
 * @param value
 * @param len
 * @return
 */
int8_t cbor_map_from_int_bytes(void *decoder, int8_t key, const uint8_t **value, size_t *len);

/**
 *
 * @param decoder
 * @param key
 * @param value
 * @param len
 * @return
 */
int8_t cbor_map_from_tstr_tstr(void *decoder, const char *key, const char **value, size_t *len);

/**
 *
 * @param decoder
 * @param map
 * @return
 */
int8_t cbor_start_decoding_map(void *decoder, void *map);

/**
 *
 * @param decoder
 * @param array
 * @return
 */
int8_t cbor_start_decoding_array(void *decoder, void *array);

/**
 * @brief Set up a CBOR encoder context.
 *
 * @param[in] encoder   Decoder context to initialize
 * @param[in] buffer    Buffer to hold CBOR-encoded data
 * @param[in] len       Maximum length of @p buffer
 */
void cbor_init_encoder(void *encoder, uint8_t *buffer, size_t len);

/**
 * @brief CBOR-encode a byte string.
 *
 * @param[in] encoder   Initialized encoder context.
 * @param[in] bytes     Byte string to encode.
 * @param[in] len       Length of @p bytes.
 *
 * @return returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_put_bstr(void *encoder, const uint8_t *bytes, size_t len);

/**
 * @brief CBOR-encode an signed integer
 *
 * @param[in] encoder   Initialized encoder context.
 * @param[in] value     Signed integer to encode.
 *
 * @return Returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_put_int8_t(void *encoder, int8_t value);

/**
 * @brief CBOR-encode an unsigned integer
 *
 * @param[in] encoder   Initialized encoder context.
 * @param[in] value     Signed integer to encode.
 *
 * @return Returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_put_uint8_t(void *encoder, uint8_t value);

/**
 * @brief Create a CBOR array with a predefined number of elements
 *
 * @param[in] encoder
 * @param[in] elements

 * @return Returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_put_array(void *encoder, int8_t elements);

/**
 * @brief Create a CBOR map with a predefined number of elements
 *
 * @param[in] encoder
 * @param[in] elements

 * @return Returns CBOR_SUCCESS on success else CBOR_FAILED.
 */
int8_t cbor_put_map(void *encoder, int8_t elements);

/**
 *
 * @param encoder
 * @param tstr
 * @return
 */
int8_t cbor_put_tstr(void *encoder, const char *tstr);

/**
 *
 * @param encoder
 * @param elements
 * @return
 */
int8_t cbor_start_bstr(void *encoder, uint16_t elements);

/**
 *
 * @param decoder
 * @param start
 * @param len
 * @return
 */
int8_t cbor_get_substream(void *decoder, const uint8_t **start, size_t *len);

/**
 *
 * @param encoder
 * @return
 */
size_t cbor_encoded_len(void *encoder);

/**
 *
 * @param decoder
 * @return
 */
int8_t cbor_skip(void *decoder);

#endif /* EDHOC_CBOR_H */
