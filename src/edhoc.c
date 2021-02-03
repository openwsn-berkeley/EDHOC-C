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

    cose_key_init(&conf->auth_key);
}

void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf) {
    ctx->conf = conf;
}

int edhoc_conf_setup(edhoc_conf_t *conf,
                     edhoc_role_t role,
                     rng_cb_t f_rng,
                     void *p_rng,
                     cred_cb_t cred_cb,
                     ad_cb_t ad1_cb,
                     ad_cb_t ad2_cb,
                     ad_cb_t ad3_cb) {

    if (role != EDHOC_IS_INITIATOR && role != EDHOC_IS_RESPONDER) {
        return EDHOC_ERR_INVALID_ROLE;
    }

    conf->role = role;

#if defined(MBEDTLS)
    if (f_rng == NULL)
        return EDHOC_ERR_RNG;
#endif

    conf->f_rng = f_rng;
    conf->p_rng = p_rng;

    // if NULL authentication of the key exchange will be skipped
    conf->f_remote_cred = cred_cb;

    // callback functions to fetch additional data that needs to be piggybacked on the key exchange
    conf->ad1 = ad1_cb;
    conf->ad2 = ad2_cb;
    conf->ad3 = ad3_cb;

    return EDHOC_SUCCESS;
}

int edhoc_conf_load_authkey(edhoc_conf_t *conf, const uint8_t *auth_key, size_t auth_key_len) {
    return cose_key_from_cbor(&conf->auth_key, auth_key, auth_key_len);
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

int edhoc_conf_load_pubkey(edhoc_conf_t *conf, const uint8_t *pub_key, size_t pub_key_len) {
    return cose_key_from_cbor(&conf->pub_key, pub_key, pub_key_len);
    return 0;
}

#endif /* EDHOC_AUTH_RAW_PUBKEY_ENABLED */

#if defined(EDHOC_AUTH_CBOR_CERT_ENABLED)

int edhoc_conf_load_cbor_cert(edhoc_conf_t *conf, const uint8_t *cbor_cert, size_t cbor_cert_len) {
    return cbor_cert_load_from_cbor(&conf->cred, cbor_cert, cbor_cert_len);

}

int edhoc_conf_load_cred_id(edhoc_conf_t *conf, const uint8_t *cred_id, size_t cred_id_len) {
    conf->cred_id = cred_id;
    conf->cred_id_len = cred_id_len;

    return EDHOC_SUCCESS;
}

#endif /* EDHOC_AUTH_CBOR_CERT_ENABLED */

int edhoc_exporter(edhoc_ctx_t *ctx, const char *label, size_t length, uint8_t *out, size_t olen) {
    int ret;
    const cipher_suite_t *suite_info;
    cose_algo_t aead;

    suite_info = edhoc_cipher_suite_from_id(ctx->session.cipher_suite);

    if (olen < length)
        return EDHOC_ERR_BUFFER_OVERFLOW;

    aead = suite_info->app_aead;

    EDHOC_CHECK_SUCCESS(crypt_edhoc_kdf(aead, ctx->session.prk_4x3m, ctx->session.th_4, label, length, out));

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}



