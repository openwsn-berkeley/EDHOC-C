#include <string.h>

#include "edhoc/edhoc.h"
#include "edhoc/credentials.h"

#include "ciphersuites.h"
#include "crypto.h"
#include "format.h"
#include "process.h"


void edhoc_ctx_init(edhoc_ctx_t *ctx) {
    memset(ctx, 0, sizeof(edhoc_ctx_t));

    ctx->correlation = CORR_UNSET;
    ctx->state = EDHOC_WAITING;

#if defined(EDHOC_DEBUG_ENABLED)
    cose_key_init(&ctx->myEphKey);
#endif
}

void edhoc_conf_init(edhoc_conf_t *conf) {
    memset(conf, 0, sizeof(edhoc_conf_t));
}

void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf, void *thCtx) {
    crypt_hash_init(thCtx);

    ctx->thCtx = thCtx;
    ctx->conf = conf;
}


int edhoc_conf_setup_role(edhoc_conf_t *conf, edhoc_role_t role) {

    if (role != EDHOC_IS_INITIATOR && role != EDHOC_IS_RESPONDER) {
        return EDHOC_ERR_UNSUPPORTED_ROLE;
    }

    conf->role = role;

    return EDHOC_SUCCESS;
}

int edhoc_conf_setup_credentials(edhoc_conf_t *conf,
                                 cose_key_t *authKey,
                                 cred_type_t credType,
                                 cred_t credCtx,
                                 cred_id_t *idCtx,
                                 edhoc_cred_cb_t fRemoteCred) {

    if (credType != CRED_TYPE_RPK && credType != CRED_TYPE_DER_CERT && credType != CRED_TYPE_CBOR_CERT) {
        return EDHOC_ERR_INVALID_CRED;
    }

    conf->myCred.credType = credType;
    conf->myCred.credCtx = credCtx;
    conf->myCred.authKey = authKey;
    conf->myCred.idCtx = idCtx;

    if (fRemoteCred == NULL) {
        return EDHOC_ERR_INVALID_CRED;
    }

    conf->f_remote_cred = fRemoteCred;

    return EDHOC_SUCCESS;
}

void edhoc_conf_setup_ad_callbacks(edhoc_conf_t *conf, ad_cb_t ad1Cb, ad_cb_t ad2Cb, ad_cb_t ad3Cb) {

    // callback functions to fetch additional data that needs to be piggybacked on the key exchange
    conf->ad1 = ad1Cb;
    conf->ad2 = ad2Cb;
    conf->ad3 = ad3Cb;
}

int edhoc_exporter(edhoc_ctx_t *ctx, const char *label, size_t length, uint8_t *out, size_t olen) {
    int ret;
    ssize_t len;
    const cipher_suite_t *cipherSuite;
    const cose_aead_t *aeadCipher;

    uint8_t infoBuf[
            4 * CBOR_HDR + sizeof(uint32_t) + EDHOC_DIGEST_SIZE + EDHOC_MAX_LABEL_SIZE + sizeof(uint32_t)] = {0};

    cipherSuite = NULL;
    aeadCipher = NULL;

    cipherSuite = edhoc_cipher_suite_from_id(ctx->session.cipherSuiteID);
    aeadCipher = cose_algo_get_aead_info(cipherSuite->appAeadCipher);

    if (olen < length || strlen(label) > EDHOC_MAX_LABEL_SIZE)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    if ((len = format_info_encode(aeadCipher->id,
                                  ctx->session.th4,
                                  label,
                                  length,
                                  infoBuf,
                                  sizeof(infoBuf))) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    EDHOC_CHECK_SUCCESS(crypt_kdf(ctx->session.prk4x3m, infoBuf, len, out, length));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx,
                          corr_t correlation,
                          method_t m,
                          cipher_suite_id_t id,
                          uint8_t *out,
                          size_t olen) {
    return proc_create_msg1(ctx, correlation, m, id, out, olen);
}

ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx, const uint8_t *msg1Buf, size_t msg1Len, uint8_t *out, size_t olen) {
    return proc_create_msg2(ctx, msg1Buf, msg1Len, out, olen);
}

ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx, const uint8_t *msg2Buf, size_t msg2Len, uint8_t *out, size_t olen) {
    return proc_create_msg3(ctx, msg2Buf, msg2Len, out, olen);
}

/**
 * @brief   Finalize the EDHOC ecxhange on the Initiator side
 *
 * @param[in,out] ctx       EDHOC context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
ssize_t edhoc_init_finalize(edhoc_ctx_t *ctx) {
    return proc_init_finalize(ctx);
}

/**
 * @brief   Finalize the EDHOC ecxhange on the Responder side
 *
 * @param[in,out] ctx       EDHOC context
 * @param[in] msg3Buf      Buffer containing EDHOC message 3
 * @param[in] msg3Len      Length of @p msg3_buf
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
ssize_t edhoc_resp_finalize(edhoc_ctx_t *ctx,
                            const uint8_t *msg3Buf,
                            size_t msg3Len,
                            bool doMsg4,
                            uint8_t *out,
                            size_t olen) {
    return proc_resp_finalize(ctx, msg3Buf, msg3Len, doMsg4, out, olen);
}

#if defined(EDHOC_DEBUG_ENABLED)

int edhoc_load_ephkey(edhoc_ctx_t *ctx, const uint8_t *ephKey, size_t ephKeyLen) {
    return cose_key_from_cbor(&ctx->myEphKey, ephKey, ephKeyLen);
}

static size_t store_conn_id(uint8_t *storage, const uint8_t *conn_id, size_t conn_id_len) {
    if (conn_id_len > EDHOC_CID_LEN) {
        return EDHOC_ERR_BUFFER_OVERFLOW;
    }

    if (conn_id == NULL || conn_id_len != 0) {
        return EDHOC_ERR_BUFFER_OVERFLOW;
    }

    memcpy(storage, conn_id, conn_id_len);

    return conn_id_len;
}

int edhoc_session_preset_cidi(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidiLen = store_conn_id(ctx->session.cidi, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

int edhoc_session_preset_cidr(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidrLen = store_conn_id(ctx->session.cidr, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

#endif /* EDHOC_DEBUG_ENABLED */
