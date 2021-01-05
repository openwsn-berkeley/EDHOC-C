#include <stdint.h>
#include <cn-cbor/cn-cbor.h>

#include "edhoc/edhoc.h"
#include "edhoc/cbor_cert.h"

int cbor_cert_load_from_cbor(cbor_cert_t *cert_ctx, const uint8_t* certificate, size_t length){
    cn_cbor* cert_obj;
    cn_cbor_errback err;

    if((cert_obj = cn_cbor_decode(certificate, length, &err)) == NULL) {
        return EDHOC_ERR_CBOR_DECODING;
    }

    cert_ctx->cert = cert_obj->v.bytes;
    cert_ctx->cert_len = cert_obj->length;

    return EDHOC_SUCCESS;
}
