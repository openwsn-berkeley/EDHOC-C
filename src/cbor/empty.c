#include "cbor.h"

#if defined(EMPTY_CBOR)

void cbor_init_decoder(void *decoder, const uint8_t *buffer, size_t len) {
    (void) decoder;
    (void) buffer;
    (void) len;
}

int8_t cbor_get_bstr(void *decoder, const uint8_t **buffer, size_t *len) {
    (void) decoder;
    (void) buffer;
    (void) len;

    return CBOR_SUCCESS;
}

int8_t cbor_get_uint8_t(void *decoder, uint8_t *value) {
    (void) decoder;
    (void) value;

    return CBOR_SUCCESS;
}

int8_t cbor_get_tstr(void *decoder, const uint8_t **tstr, size_t *len) {
    (void) decoder;
    (void) tstr;
    (void) len;

    return CBOR_SUCCESS;
}

int8_t cbor_get_int8_t(void *decoder, int8_t *value) {
    (void) decoder;
    (void) value;

    return CBOR_SUCCESS;
}

int8_t cbor_get_int32_t(void *decoder, int32_t *value) {
    (void) decoder;
    (void) value;
    return CBOR_SUCCESS;
}

uint8_t cbor_get_array(void *decoder, uint8_t *arr, size_t *len) {
    (void) decoder;
    (void) arr;
    (void) len;

    return CBOR_SUCCESS;

}

int8_t cbor_get_type(void *decoder) {
    (void) decoder;

    return CBOR_INVALID;
}

int8_t cbor_map_from_int_int(void *decoder, int8_t key, int8_t *value) {
    (void) decoder;
    (void) key;
    (void) value;

    return CBOR_SUCCESS;
}

int8_t cbor_map_from_tstr_tstr(void *decoder, const char *key, const char **value, size_t *len) {
    (void) decoder;
    (void) key;
    (void) value;
    (void) len;

    return CBOR_SUCCESS;
}

int8_t cbor_map_from_int_bytes(void *decoder, int8_t key, const uint8_t **value, size_t *len) {
    (void) decoder;
    (void) key;
    (void) value;
    (void) len;

    return CBOR_SUCCESS;
}

bool cbor_at_end(void *decoder) {
    (void) decoder;
    return CBOR_SUCCESS;
}

void cbor_init_encoder(void *encoder, uint8_t *buffer, size_t len) {
    (void) encoder;
    (void) buffer;
    (void) len;
}

int8_t cbor_put_bstr(void *encoder, const uint8_t *bytes, size_t len) {
    (void) encoder;
    (void) bytes;
    (void) len;
    return CBOR_SUCCESS;
}

int8_t cbor_put_uint(void *encoder, uint8_t value) {
    (void) encoder;
    (void) value;

    return CBOR_SUCCESS;
}

int8_t cbor_put_int(void *encoder, int8_t value) {
    (void) encoder;
    (void) value;
    return CBOR_SUCCESS;
}

int8_t cbor_put_array(void *encoder, int8_t elements) {
    (void) encoder;
    (void) elements;

    return CBOR_SUCCESS;
}

int8_t cbor_put_map(void *encoder, int8_t elements) {
    (void) encoder;
    (void) elements;

    return CBOR_SUCCESS;
}

int8_t cbor_put_tstr(void *encoder, const char *tstr) {
    (void) encoder;
    (void) tstr;

    return CBOR_SUCCESS;
}

size_t cbor_encoded_len(void *encoder) {
    (void) encoder;

    return CBOR_SUCCESS;
}

int8_t cbor_skip(void *decoder) {
    (void) decoder;

    return CBOR_SUCCESS;
}

int8_t cbor_start_decoding_map(void *decoder, void *map) {
    (void) decoder;
    (void) map;

    return CBOR_SUCCESS;
}

int8_t cbor_start_decoding_array(void *decoder, void *array) {
    (void) decoder;
    (void) array;

    return CBOR_SUCCESS;
}

int8_t cbor_get_substream(void *decoder, const uint8_t **start, size_t *len) {
    (void) decoder;
    (void) start;
    (void) len;

    return CBOR_SUCCESS;
}

#endif