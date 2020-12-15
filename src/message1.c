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

bool EDHOC_Msg1_Decode(const uint8_t *msg, size_t mSize, EDHOC_Msg1 *message) {
    cn_cbor *cbor[5] = {NULL};
    cn_cbor *final_cbor = NULL;
    uint8_t field = 0;
    uint8_t rSize;
    cn_cbor_errback cbor_err;

    while ((final_cbor = cn_cbor_decode(msg, mSize, &cbor_err)) == NULL) {
        rSize = cbor_err.pos;

        // reset the error
        memset(&cbor_err, 0, sizeof(cbor_err));
        cbor[field] = cn_cbor_decode(msg, rSize, &cbor_err);

        // if a new errors occurs something went wrong, abort
        if (cbor_err.err != CN_CBOR_NO_ERROR)
            goto fail;

        msg = &msg[rSize];
        mSize = mSize - rSize;
        field += 1;
    }

    cbor[field] = final_cbor;

    if (cbor[METHOD_CORR]->type == CN_CBOR_UINT) {
        message->method_corr = cbor[METHOD_CORR]->v.uint;
    } else {
        goto fail;
    }

    if (cbor[SUITES]->type == CN_CBOR_UINT) {
        message->suites = (cipher_suite_t *) &cbor[SUITES]->v.uint;
        message->s_size = 1;
    } else if (cbor[SUITES]->type == CN_CBOR_ARRAY) {
        message->suites = (cipher_suite_t *) cbor[SUITES]->v.bytes;
        message->s_size = cbor[SUITES]->length;
    } else {
        goto fail;
    }

    if (cbor[G_X]->type == CN_CBOR_BYTES && cbor[G_X]->length != 0) {
        message->g_x = (uint8_t *) cbor[G_X]->v.bytes;
        message->g_x_size = cbor[G_X]->length;
    } else {
        goto fail;
    }

    if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length != 0) {
        message->connection_idi = (uint8_t *) cbor[C_I]->v.bytes;
        message->ci_size = cbor[G_X]->length;
    } else if (cbor[C_I]->type == CN_CBOR_BYTES && cbor[C_I]->length == 0) {
        message->connection_idi = NULL;
        message->ci_size = 0;
    } else {
        goto fail;
    }

    if (cbor[AD_1] != NULL) {
        if (cbor[AD_1]->type == CN_CBOR_BYTES) {
            message->additional_data_1 = (uint8_t *) cbor[AD_1]->v.bytes;
            message->ad1_size = cbor[AD_1]->length;
        }
    }

    return true;

    fail:
    memset(message, 0, sizeof(EDHOC_Msg1));
    return false;
}
