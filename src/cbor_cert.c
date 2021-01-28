#include <stdint.h>

#include "cbor_internal.h"
#include "edhoc/edhoc.h"
#include "edhoc/cbor_cert.h"

int cbor_cert_load_from_cbor(cbor_cert_t *cert_ctx, const uint8_t* certificate, size_t length){
    int ret;
    ssize_t size, written;
    const uint8_t* pt;

    size = 0;
    ret = EDHOC_ERR_CBOR_DECODING;

    CBOR_CHECK_RET(cbor_bytes_decode(&pt, &cert_ctx->cert_len, certificate, size, length));
    cert_ctx->cert = pt;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}
