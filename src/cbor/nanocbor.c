#include "cbor.h"

#if defined(NANOCBOR)

#include <nanocbor/nanocbor.h>
#include <memory.h>

#endif

#if defined(NANOCBOR)

void cbor_init_decoder(void *decoder, const uint8_t *buffer, size_t len) {
    nanocbor_decoder_init((nanocbor_value_t *) decoder, buffer, len);
}

int8_t cbor_get_bstr(void *decoder, const uint8_t **buffer, size_t *len) {
    if (nanocbor_get_bstr((nanocbor_value_t *) decoder, buffer, len) == NANOCBOR_OK)
        return CBOR_SUCCESS;
    else
        return CBOR_FAILED;
}

int8_t cbor_get_uint8_t(void *decoder, uint8_t *value) {
    if (nanocbor_get_uint8((nanocbor_value_t *) decoder, value) > 0)
        return CBOR_SUCCESS;
    else
        return CBOR_FAILED;
}

int8_t cbor_get_tstr(void *decoder, const uint8_t **tstr, size_t *len) {
    if (nanocbor_get_tstr((nanocbor_value_t *) decoder, tstr, len) == NANOCBOR_OK)
        return CBOR_SUCCESS;
    else
        return CBOR_FAILED;
}

int8_t cbor_get_int8_t(void *decoder, int8_t *value) {
    if (nanocbor_get_int8((nanocbor_value_t *) decoder, value) > 0)
        return CBOR_SUCCESS;
    else
        return CBOR_FAILED;
}

int8_t cbor_get_int32_t(void *decoder, int32_t *value) {
    if (nanocbor_get_int32((nanocbor_value_t *) decoder, value) > 0)
        return CBOR_SUCCESS;
    else
        return CBOR_FAILED;
}

uint8_t cbor_get_array(void *decoder, uint8_t *arr, size_t *len) {
    (void) len;
    (void) arr;
    nanocbor_value_t array;

    if (nanocbor_enter_array((nanocbor_value_t *) decoder, &array) != NANOCBOR_OK)
        return CBOR_FAILED;

    while (!nanocbor_at_end(&array)) {

    }

    return CBOR_SUCCESS;

}

int8_t cbor_get_type(void *decoder) {
    uint8_t type;

    switch (nanocbor_get_type((nanocbor_value_t *) decoder)) {
        case NANOCBOR_TYPE_UINT:
            type = CBOR_UINT;
            break;
        case NANOCBOR_TYPE_NINT:
            type = CBOR_NINT;
            break;
        case NANOCBOR_TYPE_BSTR:
            type = CBOR_BSTR;
            break;
        case NANOCBOR_TYPE_TSTR:
            type = CBOR_TSTR;
            break;
        case NANOCBOR_TYPE_ARR:
            type = CBOR_ARRAY;
            break;
        case NANOCBOR_TYPE_MAP:
            type = CBOR_MAP;
            break;
        case NANOCBOR_TYPE_TAG:
            type = CBOR_TAG;
            break;
        case NANOCBOR_TYPE_FLOAT:
            type = CBOR_FLOAT;
            break;
        default:
            type = CBOR_INVALID;
            break;
    }

    return type;
}

int8_t cbor_map_from_int_int(void *decoder, int8_t key, int8_t *value) {
    int32_t current_key;
    nanocbor_value_t map;

    if (nanocbor_enter_map((nanocbor_value_t *) decoder, &map) != NANOCBOR_OK)
        return CBOR_FAILED;

    while (!nanocbor_at_end(&map)) {
        if (nanocbor_get_int32(&map, &current_key) > 0) {
            if (current_key == key) {
                if (nanocbor_get_int8(&map, value) > 0) {
                    return CBOR_SUCCESS;
                } else {
                    return CBOR_FAILED;
                }
            } else {
                if (nanocbor_skip(&map) != NANOCBOR_OK) {
                    return CBOR_FAILED;
                }
            }
        } else {
            // skip key
            nanocbor_skip(&map);
            // skip value
            nanocbor_skip(&map);
        }
    }

    return CBOR_FAILED;
}

int8_t cbor_map_from_tstr_tstr(void *decoder, const char *key, const char **value, size_t *value_len) {
    const uint8_t *current_key;
    size_t key_len;
    nanocbor_value_t map;

    if (nanocbor_enter_map((nanocbor_value_t *) decoder, &map) != NANOCBOR_OK)
        return CBOR_FAILED;

    while (!nanocbor_at_end(&map)) {
        if (nanocbor_get_tstr(&map, &current_key, &key_len) == NANOCBOR_OK) {
            if ((strlen(key) == key_len) && (strncmp((const char *) current_key, key, key_len)) == 0) {
                if (nanocbor_get_tstr(&map, (const uint8_t **) value, value_len) == NANOCBOR_OK) {
                    return CBOR_SUCCESS;
                } else {
                    return CBOR_FAILED;
                }
            } else {
                if (nanocbor_skip(&map) != NANOCBOR_OK) {
                    return CBOR_FAILED;
                }
            }
        } else {
            // skip key
            nanocbor_skip(&map);
            // skip value
            nanocbor_skip(&map);
        }
    }

    return CBOR_FAILED;
}

int8_t cbor_map_from_int_bytes(void *decoder, int8_t key, const uint8_t **value, size_t *len) {
    int8_t current_key;
    nanocbor_value_t map;

    if (nanocbor_enter_map((nanocbor_value_t *) decoder, &map) != NANOCBOR_OK)
        return CBOR_FAILED;

    while (!nanocbor_at_end(&map)) {
        if (nanocbor_get_int8(&map, &current_key) > 0) {
            if (current_key == key) {
                if (nanocbor_get_bstr(&map, value, len) == NANOCBOR_OK) {
                    return CBOR_SUCCESS;
                }
            } else {
                if (nanocbor_skip(&map) != NANOCBOR_OK) {
                    return CBOR_FAILED;
                }
            }
        } else {
            // skip key
            nanocbor_skip(&map);
            // skip value
            nanocbor_skip(&map);
        }
    }

    return CBOR_FAILED;
}

int8_t cbor_get_substream(void* decoder, const uint8_t** start, size_t* len){
    if (nanocbor_get_subcbor(decoder, start, len) == NANOCBOR_OK){
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_start_decoding_map(void *decoder, void *map) {
    if (nanocbor_enter_map(decoder, map) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_start_decoding_array(void *decoder, void *array) {
    if (nanocbor_enter_array(decoder, array) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

bool cbor_at_end(void *decoder) {
    return nanocbor_at_end(decoder);
}

void cbor_init_encoder(void *encoder, uint8_t *buffer, size_t len) {
    nanocbor_encoder_init((nanocbor_encoder_t *) encoder, buffer, len);
}

int8_t cbor_put_bstr(void *encoder, const uint8_t *bytes, size_t len) {
    if (nanocbor_put_bstr(encoder, bytes, len) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_put_uint8_t(void *encoder, uint8_t value) {
    if (nanocbor_fmt_uint((nanocbor_encoder_t *) encoder, value) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_put_int8_t(void *encoder, int8_t value) {
    if (nanocbor_fmt_int((nanocbor_encoder_t *) encoder, value) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_put_array(void *encoder, int8_t elements) {
    if (nanocbor_fmt_array((nanocbor_encoder_t *) encoder, elements) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_put_map(void *encoder, int8_t elements) {
    if (nanocbor_fmt_map((nanocbor_encoder_t *) encoder, elements) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_put_tstr(void *encoder, const char *tstr) {
    if (nanocbor_put_tstr((nanocbor_encoder_t *) encoder, tstr) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}

int8_t cbor_start_bstr(void *encoder, uint16_t elements) {
    if (nanocbor_fmt_bstr(encoder, elements) < 0) {
        return CBOR_FAILED;
    } else {
        return CBOR_SUCCESS;
    }
}

size_t cbor_encoded_len(void *encoder) {
    return nanocbor_encoded_len((nanocbor_encoder_t *) encoder);
}

int8_t cbor_skip(void *decoder) {
    if (nanocbor_skip((nanocbor_value_t *) decoder) == NANOCBOR_OK) {
        return CBOR_SUCCESS;
    } else {
        return CBOR_FAILED;
    }
}


#endif


