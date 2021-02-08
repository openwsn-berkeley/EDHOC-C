#include <string.h>

#include "edhoc/edhoc.h"
#include "cipher_suites.h"

#include "crypto.h"
#include "credentials.h"


void edhoc_ctx_init(edhoc_ctx_t *ctx) {
    memset(ctx, 0, sizeof(edhoc_ctx_t));
    ctx->correlation = CORR_UNSET;

    cose_key_init(&ctx->local_eph_key);
    cose_key_init(&ctx->remote_eph_key);
}

void edhoc_conf_init(edhoc_conf_t *conf) {
    memset(conf, 0, sizeof(edhoc_conf_t));

    cose_key_init(&conf->local_cred.auth_key);
}

void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf) {
    ctx->conf = conf;
}

int edhoc_conf_load_credentials(edhoc_conf_t *conf, cred_type_t t, void *local_cred, cred_cb_t remote_cred_cb) {

    if (local_cred == NULL || (t > CRED_TYPE_RPK || t < CRED_TYPE_CBOR_CERT))
        return EDHOC_ERR_INVALID_CRED;

    conf->local_cred.cred_type = t;
    conf->local_cred.cred_pt = local_cred;

    // if NULL authentication of the key exchange will be skipped
    conf->f_remote_cred = remote_cred_cb;

    return EDHOC_SUCCESS;
}

int edhoc_conf_setup(edhoc_conf_t *conf,
                     edhoc_role_t role,
                     ad_cb_t ad1_cb,
                     ad_cb_t ad2_cb,
                     ad_cb_t ad3_cb) {

    if (role != EDHOC_IS_INITIATOR && role != EDHOC_IS_RESPONDER) {
        return EDHOC_ERR_INVALID_ROLE;
    }

    conf->role = role;

    // callback functions to fetch additional data that needs to be piggybacked on the key exchange
    conf->ad1 = ad1_cb;
    conf->ad2 = ad2_cb;
    conf->ad3 = ad3_cb;

    return EDHOC_SUCCESS;
}

int edhoc_conf_load_authkey(edhoc_conf_t *conf, const uint8_t *auth_key, size_t auth_key_len) {
    return cose_key_from_cbor(&conf->local_cred.auth_key, auth_key, auth_key_len);
}

#if defined(EDHOC_DEBUG_ENABLED)

int edhoc_load_ephkey(edhoc_ctx_t *ctx, const uint8_t *eph_key, size_t eph_key_len) {
    return cose_key_from_cbor(&ctx->local_eph_key, eph_key, eph_key_len);
}

static size_t store_conn_id(uint8_t *storage, const uint8_t *conn_id, size_t conn_id_len) {
    if (conn_id_len > EDHOC_CID_MAX_LEN)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    if (conn_id == NULL && conn_id_len != 0)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    memcpy(storage, conn_id, conn_id_len);

    return conn_id_len;
}

int edhoc_session_preset_cidi(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidi_len = store_conn_id(ctx->session.cidi, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

int edhoc_session_preset_cidr(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len) {
    ctx->session.cidr_len = store_conn_id(ctx->session.cidr, conn_id, conn_id_len);
    return EDHOC_SUCCESS;
}

#endif

#if defined(EDHOC_AUTH_RAW_PUBKEY_ENABLED)

void edhoc_cred_pub_key_init(rpk_t *key) {
    memset(key, 0, sizeof(rpk_t));
}

int edhoc_cred_load_pub_key(rpk_t *ctx, const uint8_t *pub_key, size_t pub_key_len) {
    return cred_rpk_load_from_cbor(ctx, pub_key, pub_key_len);
}

#endif /* EDHOC_AUTH_RAW_PUBKEY_ENABLED */

#if defined(EDHOC_AUTH_CBOR_CERT_ENABLED)

void edhoc_cred_cbor_cert_init(cbor_cert_t *cert_ctx) {
    memset(cert_ctx, 0, sizeof(cbor_cert_t));
}

int edhoc_cred_load_cbor_cert(cbor_cert_t *cert_ctx, const uint8_t *cbor_cert, size_t cbor_cert_len) {
    return cred_cert_load_from_cbor(cert_ctx, cbor_cert, cbor_cert_len);
}

#endif /* EDHOC_AUTH_CBOR_CERT_ENABLED */

int edhoc_conf_load_cred_id(edhoc_conf_t *conf,
                            const uint8_t *cred_id,
                            cred_id_type_t cred_id_type,
                            size_t cred_id_len) {
    conf->local_cred.cred_id = cred_id;
    conf->local_cred.cred_id_type = cred_id_type;
    conf->local_cred.cred_id_len = cred_id_len;

    return EDHOC_SUCCESS;
}

int edhoc_exporter(edhoc_ctx_t *ctx, const char *label, size_t length, uint8_t *out, size_t olen) {
    int ret;
    const cipher_suite_t *suite_info;
    cose_algo_t aead;

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (olen < length)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    aead = suite_info->app_aead;

    EDHOC_CHECK_SUCCESS(crypt_kdf(aead, ctx->session.prk_4x3m, ctx->session.th_4, label, length, out));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}



