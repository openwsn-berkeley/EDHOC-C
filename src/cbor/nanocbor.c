#include <nanocbor/nanocbor.h>
#include <edhoc/edhoc.h>

#include "cbor_internal.h"

#if defined(NANOCBOR)

ssize_t cbor_int_encode(int value, uint8_t *buffer, size_t offset, size_t total) {
    nanocbor_encoder_t encoder;

    nanocbor_encoder_init(&encoder, buffer + offset, total - offset);
    if (nanocbor_fmt_int(&encoder, value) < EDHOC_SUCCESS)
        return EDHOC_ERR_CBOR_ENCODING;

    // TODO: check with Koen, why does nanocbor_fmt_int does not return number of written bytes?
    return nanocbor_encoded_len(&encoder);
}

ssize_t cbor_bytes_encode(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total) {
    nanocbor_encoder_t encoder;

    nanocbor_encoder_init(&encoder, buffer + offset, total - offset);
    if (nanocbor_put_bstr(&encoder, bytes, bytes_len) < EDHOC_SUCCESS)
        return EDHOC_ERR_CBOR_ENCODING;

    // TODO: check with Koen, why does nanocbor_put_bstr does not return number of written bytes?
    return nanocbor_encoded_len(&encoder);
}

ssize_t cbor_string_encode(const char *string, uint8_t *buffer, size_t offset, size_t total) {
    nanocbor_encoder_t encoder;

    nanocbor_encoder_init(&encoder, buffer + offset, total - offset);
    if (nanocbor_put_tstr(&encoder, string) < EDHOC_SUCCESS)
        return EDHOC_ERR_CBOR_ENCODING;

    // TODO: check with Koen, why does nanocbor_put_bstr does not return number of written bytes?
    return nanocbor_encoded_len(&encoder);
}

ssize_t cbor_create_array(uint8_t *buffer, uint8_t elements, size_t offset, size_t total) {
    nanocbor_encoder_t encoder;

    nanocbor_encoder_init(&encoder, buffer + offset, total - offset);
    if (nanocbor_fmt_array(&encoder, elements) < EDHOC_SUCCESS)
        return EDHOC_ERR_CBOR_ENCODING;

    return nanocbor_encoded_len(&encoder);
}

ssize_t cbor_array_append_int(int value, uint8_t *buffer, size_t offset, size_t total) {
    return cbor_int_encode(value, buffer, offset, total);
}

ssize_t cbor_array_append_bytes(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total) {
    return cbor_bytes_encode(bytes, bytes_len, buffer, offset, total);
}

ssize_t cbor_array_append_string(const char *string, uint8_t *buffer, size_t offset, size_t total) {
    return cbor_string_encode(string, buffer, offset, total);
}

#endif


