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


ssize_t cbor_int_encode(int value, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_bytes_encode(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_string_encode(const char *string, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_create_array(uint8_t *buffer, uint8_t elements, size_t offset, size_t total);

ssize_t cbor_array_append_int(int value, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_array_append_bytes(const uint8_t* bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total);

ssize_t cbor_array_append_string(const char* string, uint8_t *buffer, size_t offset, size_t total);

#endif /* EDHOC_CBOR_INTERNAL_H */
