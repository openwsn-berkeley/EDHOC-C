#include <cn-cbor/cn-cbor.h>
#include <edhoc/edhoc.h>

#include "cbor_internal.h"

#if defined(CN_CBOR)

ssize_t cbor_int_encode(int value, uint8_t *buffer, size_t offset, size_t total) {
    cn_cbor *int_value;
    cn_cbor_errback err;

    if ((int_value = cn_cbor_int_create(value, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    };

    return cn_cbor_encoder_write(buffer + offset, 0, total - offset, int_value);
}

ssize_t cbor_bytes_encode(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total) {
    cn_cbor *bytes_data;
    cn_cbor_errback err;

    if ((bytes_data = cn_cbor_data_create(bytes, bytes_len, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    return cn_cbor_encoder_write(buffer + offset, 0, total - offset, bytes_data);
}

ssize_t cbor_create_array(uint8_t *buffer, uint8_t elements, size_t offset, size_t total) {
    cn_cbor *array;
    cn_cbor_errback err;

    (void) elements;
    (void) offset;

    if ((array = cn_cbor_array_create(&err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    return cn_cbor_encoder_write(buffer, 0, total, array);
}

ssize_t cbor_array_append_int(int value, uint8_t *buffer, size_t offset, size_t total) {
    cn_cbor *array;
    cn_cbor *int_value;
    cn_cbor_errback err;

    // decode previously encoded CBOR array
    if ((array = cn_cbor_decode(buffer, offset, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    if ((int_value = cn_cbor_int_create(value, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    if (!cn_cbor_array_append(array, int_value, &err)) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    return (cn_cbor_encoder_write(buffer, 0, total, array) - offset);
}

ssize_t cbor_array_append_bytes(const uint8_t *bytes, size_t bytes_len, uint8_t *buffer, size_t offset, size_t total) {
    cn_cbor *array;
    cn_cbor *bytes_data;
    cn_cbor_errback err;

    // decode previously encoded CBOR array
    if ((array = cn_cbor_decode(buffer, offset, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    if ((bytes_data = cn_cbor_data_create(bytes, bytes_len, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    };

    if (!cn_cbor_array_append(array, bytes_data, &err)) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    return (cn_cbor_encoder_write(buffer, 0, total, array) - offset);
}

ssize_t cbor_array_append_string(const char *string, uint8_t *buffer, size_t offset, size_t total) {
    cn_cbor *array;
    cn_cbor *string_data;
    cn_cbor_errback err;

    // decode previously encoded CBOR array
    if ((array = cn_cbor_decode(buffer, offset, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    if ((string_data = cn_cbor_string_create(string, &err)) == NULL) {
        return EDHOC_ERR_CBOR_ENCODING;
    };

    if (!cn_cbor_array_append(array, string_data, &err)) {
        return EDHOC_ERR_CBOR_ENCODING;
    }

    return (cn_cbor_encoder_write(buffer, 0, total, array) - offset);
}

#endif