#include <stdint.h>
#include <string.h>

#include "cbor.h"
#include "edhoc/edhoc.h"
#include "credentials.h"
#include "cose.h"

int cred_cert_load_from_cbor(cbor_cert_t *ctx, const uint8_t *cert_buffer, size_t buflen) {
    int ret;

    // TODO: properly analyze and decode cbor cert

    ctx->buffer = cert_buffer;
    ctx->buflen = buflen;

    ret = EDHOC_SUCCESS;
    return ret;
}

int cred_rpk_load_from_cbor(rpk_t *ctx, const uint8_t *rpk_buffer, size_t buflen) {
    int ret;

    // TODO: properly analyze and decode RPK

    ctx->buffer = rpk_buffer;
    ctx->buflen = buflen;


    ret = EDHOC_SUCCESS;
    return ret;
}

ssize_t cred_get_cred_bytes(cred_container_t* cred, const uint8_t **ptr) {
    ssize_t ret;

    ret = EDHOC_ERR_INVALID_CRED;

    if (cred->cred_type == CRED_TYPE_CBOR_CERT) {
#if defined(EDHOC_AUTH_CBOR_CERT_ENABLED)
        *ptr = ((cbor_cert_t *) cred->cred_pt)->buffer;
        ret = ((cbor_cert_t *) cred->cred_pt)->buflen;
#endif
    } else {
#if defined(EDHOC_AUTH_RAW_PUBKEY_ENABLED)
        *ptr = ((rpk_t *) cred->cred_pt)->buffer;
        ret = ((rpk_t *) cred->cred_pt)->buflen;
#endif
    }

    return ret;
}

ssize_t cred_get_cred_id_bytes(cred_container_t* cred, uint8_t *out, size_t olen) {
    ssize_t ret;
    ssize_t size, written;
    size_t bufsize;
    const uint8_t *pt;
    uint8_t tmp;

    size = 0;
    ret = EDHOC_ERR_INVALID_CRED;

    if (cred->cred_id_len == 0 || cred->cred_id == NULL || out == NULL || olen == 0)
        goto exit;

    switch (cred->cred_type) {
        case CRED_ID_TYPE_X5T:
            if (olen >= cred->cred_id_len) {
                memcpy(out, cred->cred_id, cred->cred_id_len);
                ret = cred->cred_id_len;
            } else {
                ret = EDHOC_ERR_BUFFER_OVERFLOW;
            }
            break;
        case CRED_ID_TYPE_KID:
            // check if KID
            pt = &tmp;
            cbor_map_get_int_bytes(COSE_HEADER_MAP_PARAM_KID, &pt, &bufsize, cred->cred_id, 0, cred->cred_id_len);

            if (bufsize > 1) {
                if (bufsize <= olen) {
                    // TODO: CBOR encode ?
                } else {
                    ret = EDHOC_ERR_BUFFER_OVERFLOW;
                }
            } else if (bufsize == 1) {
                // byte string encoder for |bstr| == 1
                memcpy(&tmp, pt, bufsize);
                tmp -= 24;
                CBOR_CHECK_RET(cbor_int_encode((int8_t )tmp, out, 0, olen));
                ret = size;
            } else {
                ret = EDHOC_ERR_INVALID_CRED;
            }
            break;
        case CRED_ID_TYPE_X5U:
        default:
            ret = EDHOC_ERR_INVALID_CRED;
            break;
    }

    exit:
    return ret;
}
