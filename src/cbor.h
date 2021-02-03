#ifndef EDHOC_CBOR_INTERNAL_H
#define EDHOC_CBOR_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>

#define CBOR_CHECK_RET(enc)  \
if ((written = (enc)) < 0) { \
    size = written;                    \
    goto exit;                         \
} else {                               \
    size += written;                   \
}

/**
 * DECODING ROUTINES
 */

/**
 * @brief Decode a CBOR encoded integer
 *
 * @param[out] value    Holds the decoded integer on success else is set to NULL
 * @param[in] buffer    Buffer holding the CBOR encoded integer
 * @param[in] total     Total length of @p buffer
 */
ssize_t cbor_int_decode(int *value, const uint8_t *buffer, size_t offset, size_t total);

/**
 * @brief Decode a CBOR encoded byte string
 *
 * @param[out] out      Pointer that will be set to the decoded byte string on success, else NULL
 * @param[out] len      On success output the length of the byte string
 * @param[in] buffer    Buffer holding the CBOR encoded byte string
 * @param[in] total     Total length of @p buffer
 */
ssize_t cbor_bytes_decode(const uint8_t **out, size_t *len, const uint8_t *buffer, size_t offset, size_t total);

/**
 *
 * @brief Extract from a CBOR map an integer value mapped to an int key
 *
 * @param[in] key       Key to search for in the CBOR map
 * @param[out] value    Stores the integer on successfull decode, otherwise NULL
 * @param[in] buffer    Buffer holding the CBOR encoded byte map
 * @param[in] total     Total length of @p buffer
 */
void cbor_map_get_int_int(int key, int* value, const uint8_t *buffer, size_t offset, size_t total);

/**
 * @brief Extract from a CBOR map a bytes value mapped to an int key
 *
 * @param[in] key       Key to search for in the CBOR map
 * @param[out] value    Buffer where the value extracted from the map is stored
 * @param[in,out] len   On input the maximum size of the buffer, on output the length of the stored value
 * @param[in] buffer    CBOR encoded buffer
 * @param[in] total     Total size of the CBOR encoded buffer
 */
void cbor_map_get_int_bytes(int key, const uint8_t** out, size_t *len, const uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_suites_decode(uint8_t **out, size_t *len, const uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_bstr_id_decode(uint8_t **out, size_t *len, const uint8_t *buffer, size_t offset, size_t total);

/**
 * ENCODING ROUTINES
 */

ssize_t cbor_int_encode(int value, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_bytes_encode(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_string_encode(const char *string, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_create_map(uint8_t *buffer, uint8_t elements, size_t offset, size_t total);

ssize_t cbor_create_array(uint8_t *buffer, uint8_t elements, size_t offset, size_t total);

ssize_t cbor_array_append_int(int value, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_array_append_bytes(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_array_append_string(const char *string, uint8_t *buffer, size_t offset, size_t total);

#endif /* EDHOC_CBOR_INTERNAL_H */
