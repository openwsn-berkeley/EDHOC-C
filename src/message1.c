#include <edhoc/edhoc.h>
#include <cn-cbor/cn-cbor.h>
#include <string.h>

enum Msg1_Fields {
    METHOD_CORR,
    SUITES,
    G_X,
    C_I,
    AD_1,
};

int8_t EDHOC_Msg1_Build(EDHOC_ctx_t *ctx, corr_t correlation, method_t method, const uint8_t *s, size_t s_len,
                        const uint8_t *g_x, size_t g_x_len, const uint8_t *cid, size_t cid_len,
                        const uint8_t *aad1, size_t aad1_len) {
    uint8_t method_corr;

    memset(&ctx->message_1, 0, sizeof(EDHOC_Msg1_t));

    method_corr = method * 4 + correlation;

    ctx->message_1.method_corr = method_corr;
    ctx->message_1.suites = s;
    ctx->message_1.s_size = s_len;

    // the selected cipher suite is always the first element.
    ctx->message_1.selected = ctx->message_1.suites[0];

    ctx->message_1.g_x = g_x;
    ctx->message_1.g_x_size = g_x_len;

    if (cid == NULL && cid_len != 0) {
        return -1;
    } else if (cid_len > 1 || cid_len == 0) {
        ctx->message_1.connection_idi = (uint8_t *) cid;
    } else {
        ctx->message_1.connection_idi[0] = cid[0] - 24;
    }
    ctx->message_1.ci_size = cid_len;

    if (aad1 == NULL && aad1_len != 0) {
        return -1;
    } else {
        ctx->message_1.additional_data_1 = aad1;
        ctx->message_1.ad1_size = aad1_len;
    }

    return 0;
}

ssize_t EDHOC_Msg1_Encode(const EDHOC_ctx_t *ctx, uint8_t *buf, size_t bsize) {
    ssize_t msg_size;
    cn_cbor *obj;
    cn_cbor_errback errp;

    // reset output buffer
    memset(buf, 0, bsize);
    msg_size = 0;

    if ((obj = cn_cbor_int_create(ctx->message_1.method_corr, &errp)) == NULL) {
        return -1;
    };
    msg_size += cn_cbor_encoder_write(buf, 0, bsize, obj);

    if (ctx->message_1.s_size == 1) {
        if ((obj = cn_cbor_int_create(*ctx->message_1.suites, &errp)) == NULL) {
            return -1;
        };
    } else {
        if ((obj = cn_cbor_data_create(ctx->message_1.suites, ctx->message_1.s_size, &errp)) == NULL) {
            return -1;
        };
    }
    msg_size += cn_cbor_encoder_write(buf, msg_size, bsize, obj);

    if ((obj = cn_cbor_data_create(ctx->message_1.g_x, ctx->message_1.g_x_size, &errp)) == NULL) {
        return -1;
    }
    msg_size += cn_cbor_encoder_write(buf, msg_size, bsize, obj);

    if (ctx->message_1.ci_size == 1) {
        if ((obj = cn_cbor_int_create(*ctx->message_1.connection_idi, &errp)) == NULL) {
            return -1;
        };
        msg_size += cn_cbor_encoder_write(buf, msg_size, bsize, obj);
    } else {
        if ((obj = cn_cbor_data_create(ctx->message_1.connection_idi, ctx->message_1.ci_size, &errp)) == NULL) {
            return -1;
        };
        msg_size += cn_cbor_encoder_write(buf, msg_size, bsize, obj);
    }

    if (ctx->message_1.ad1_size != 0 && ctx->message_1.additional_data_1 != NULL) {
        if ((obj = cn_cbor_data_create(ctx->message_1.additional_data_1, ctx->message_1.ad1_size, &errp)) == NULL) {
            return -1;
        };
        msg_size += cn_cbor_encoder_write(buf, msg_size, bsize, obj);
    }

    return msg_size;
}

int8_t EDHOC_Msg1_Decode(EDHOC_ctx_t *ctx, const uint8_t *buf, size_t bsize) {
    cn_cbor *cbor[5] = {NULL};
    cn_cbor *final_cbor = NULL;
    uint8_t field = 0;
    uint8_t rSize;
    cn_cbor_errback cbor_err;

    while ((final_cbor = cn_cbor_decode(buf, bsize, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(buf, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            goto fail;

        buf = &buf[rSize];
        bsize = bsize - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    if (cbor[METHOD_CORR]->type == CN_CBOR_UINT) {
        ctx->message_1.method_corr = cbor[METHOD_CORR]->v.uint;
    } else {
        goto fail;
    }

    if (cbor[SUITES]->type == CN_CBOR_UINT) {
        ctx->message_1.suites = (const uint8_t *) cbor[SUITES]->v.uint;
        ctx->message_1.s_size = 1;
        ctx->message_1.selected = *((cipher_suite_t *) &cbor[SUITES]->v.uint);
    } else if (cbor[SUITES]->type == CN_CBOR_ARRAY) {
        ctx->message_1.suites = cbor[SUITES]->v.bytes;
        ctx->message_1.s_size = cbor[SUITES]->length;
        ctx->message_1.selected = *((cipher_suite_t *) &cbor[SUITES]->v.bytes[0]);
    } else {
        goto fail;
    }

    if (cbor[G_X]->type == CN_CBOR_BYTES && cbor[G_X]->length != 0) {
        ctx->message_1.g_x = (uint8_t *) cbor[G_X]->v.bytes;
        ctx->message_1.g_x_size = cbor[G_X]->length;
    } else {
        goto fail;
    }

    if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length != 0) {
        ctx->message_1.connection_idi = (uint8_t *) cbor[C_I]->v.bytes;
        ctx->message_1.ci_size = cbor[G_X]->length;
    } else if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length == 0) {
        ctx->message_1.connection_idi = NULL;
        ctx->message_1.ci_size = 0;
    } else {
        goto fail;
    }

    if (cbor[AD_1] != NULL) {
        if (cbor[AD_1]->type == CN_CBOR_BYTES) {
            ctx->message_1.additional_data_1 = (uint8_t *) cbor[AD_1]->v.bytes;
            ctx->message_1.ad1_size = cbor[AD_1]->length;
        }
    }

    return 0;

    fail:
    memset(&ctx->message_1, 0, sizeof(struct EDHOC_Msg1));
    return -1;
}
