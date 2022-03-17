#include <stdint.h>
#include <string.h>

#include "edhoc/cose.h"
#include "edhoc/credentials.h"
#include "cbor.h"

#if defined(NANOCBOR)

#include <nanocbor/nanocbor.h>

#else
#error "No CBOR backend enabled"
#endif

#if defined(EDHOC_AUTH_X509_CERT)
#if defined(MBEDTLS)

#include <mbedtls/x509_crt.h>

#else
#error "No X509 backend enabled"
#endif
#endif


void cred_c509_init(c509_t *c509Ctx) {
    memset(c509Ctx, 0, sizeof(c509_t));
}


#if defined(EDHOC_AUTH_X509_CERT)

void cred_x509_init(void *x509Ctx) {
#if defined(MBEDTLS)
    mbedtls_x509_crt_init(x509Ctx);
#else
#error "No X509 backend enabled"
    (void) x509Ctx;
#endif
}

#endif


void cred_rpk_init(rpk_t *rpkCtx) {
    memset(rpkCtx, 0, sizeof(rpk_t));
}


void cred_id_init(cred_id_t *credIdCtx) {
    memset(credIdCtx, 0, sizeof(cred_id_t));

    cose_header_init(credIdCtx->map);
}

#if defined(EDHOC_AUTH_X509_CERT)

int cred_x509_from_der(void *x509Ctx, const uint8_t *in, size_t ilen) {
    const uint8_t *p;
    size_t len;

#if defined(NANOCBOR)
    nanocbor_value_t decoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, in, ilen);

    if (cbor_get_bstr(&decoder, &p, &len) != CBOR_SUCCESS) {
        return EDHOC_ERR_CBOR_DECODING;
    }

    // if not at end something is wrong
    if (!cbor_at_end(&decoder))
        return EDHOC_ERR_INVALID_CRED;

#if defined(MBEDTLS)
    if (mbedtls_x509_crt_parse_der((mbedtls_x509_crt *) x509Ctx, in, ilen) == 0) {
        return EDHOC_SUCCESS;
    } else {
        // TODO: since currently the test vectors all contain invalid test vectors we are still kind of parsing the cert
        // TODO: This needs to be removed once we are dealing with real certificates
        ((mbedtls_x509_crt *) x509Ctx)->raw.p = (unsigned char *) p;
        ((mbedtls_x509_crt *) x509Ctx)->raw.len = len;
        return EDHOC_ERR_INVALID_CRED;
    }
#else
#error No X509 backend enabled
    (void) x509Ctx;
    return EDHOC_ERR_INVALID_CRED;
#endif
}

#endif

static int parse_c509_name(void *decoder, const uint8_t **p, size_t *len) {
    int ret;

    if (cbor_get_type(decoder) == CBOR_TSTR) {
        if (cbor_get_tstr(decoder, p, len) != CBOR_SUCCESS) {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }
    } else if (cbor_get_type(decoder) == CBOR_BSTR) {
        if (cbor_get_bstr(decoder, p, len) != CBOR_SUCCESS) {
            EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
        }
    } else {
        // TODO: cbor array?
        cbor_skip(decoder);
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int cred_id_from_cbor(cred_id_t *credIdCtx, const uint8_t *in, size_t ilen) {
    int ret;

    EDHOC_CHECK_SUCCESS(cose_header_parse(credIdCtx->map, in, ilen));

    credIdCtx->cred = in;
    credIdCtx->credLen = ilen;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int cred_c509_from_cbor(c509_t *c509Ctx, const uint8_t *in, size_t ilen) {
    int ret;

#if defined(NANOCBOR)
    nanocbor_value_t decoder;
#else
#error "No CBOR backend enabled"
#endif

    c509Ctx->raw.p = in;
    c509Ctx->raw.length = ilen;

    cbor_init_decoder(&decoder, in, ilen);

    if (cbor_get_uint8_t(&decoder, (uint8_t *) &c509Ctx->cborCertificateType) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    if (c509Ctx->cborCertificateType != C509_NATIVE && c509Ctx->cborCertificateType != C509_ENCODED) {
        EDHOC_FAIL(EDHOC_ERR_INVALID_CRED);
    }

    if (cbor_get_bstr(&decoder, &c509Ctx->serialNumber.p, &c509Ctx->serialNumber.length) !=
        CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    EDHOC_CHECK_SUCCESS(parse_c509_name(&decoder, &c509Ctx->issuer.p, &c509Ctx->issuer.length));

    // TODO: parse time
    cbor_skip(&decoder);
    cbor_skip(&decoder);

    EDHOC_CHECK_SUCCESS(parse_c509_name(&decoder, &c509Ctx->subject.p, &c509Ctx->subject.length));

    if (cbor_get_int32_t(&decoder, &c509Ctx->subjectPublicKeyAlgorithm) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    if (cbor_get_bstr(&decoder, &c509Ctx->subjectPublicKey.p, &c509Ctx->subjectPublicKey.length) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    // TODO: parse extensions
    cbor_skip(&decoder);

    if (cbor_get_int32_t(&decoder, &c509Ctx->issuerSignatureAlgorithm) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    // ctx->tbs.cred = in;
    // ctx->tbs.credLen = 0;

    if (cbor_get_bstr(&decoder, &c509Ctx->issuerSignatureValue.p, &c509Ctx->issuerSignatureValue.length) !=
        CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}


int cred_rpk_from_cbor(rpk_t *rpkCtx, const uint8_t *in, size_t ilen) {
    int ret;
    size_t subject_name_len;

#if defined(NANOCBOR)
    nanocbor_value_t decoder;
#else
#error "No CBOR backend enabled"
#endif

    cbor_init_decoder(&decoder, in, ilen);

    if (cbor_get_type(&decoder) != CBOR_MAP) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    EDHOC_CHECK_SUCCESS(cose_key_from_cbor(&rpkCtx->coseKey, in, ilen));

    if (cbor_map_from_tstr_tstr(&decoder, "subject name", &rpkCtx->subjectName, &subject_name_len) != CBOR_SUCCESS) {
        EDHOC_FAIL(EDHOC_ERR_CBOR_DECODING);
    }

    rpkCtx->raw.p = in;
    rpkCtx->raw.length = ilen;

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

