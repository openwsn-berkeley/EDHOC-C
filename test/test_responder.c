#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <edhoc/edhoc.h>
#include <stdlib.h>

#include "json.h"

int test_message2_encoding(
        const uint8_t *eph_key,
        size_t eph_key_len,
        const uint8_t *auth_key,
        size_t auth_key_len,
        const uint8_t *cid,
        size_t cid_len,
        const uint8_t *msg1,
        size_t msg1_len,
        uint8_t* cbor_certificate,
        size_t cert_len,
        uint8_t* cred_id,
        size_t cred_id_len,
        const uint8_t *expected_msg,
        size_t expected_len) {

    int ret;
    uint8_t mbuf[200];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

#if defined(MBEDTLS)
    char *pers = "edhoc_responder";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // create a strong randomness source
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    EDHOC_CHECK_RET(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, mbedtls_entropy_func, &entropy, NULL));
#elif defined(WOLFSSL)
    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL));
#endif


    EDHOC_CHECK_RET(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len));
    EDHOC_CHECK_RET(edhoc_conf_load_cborcert(&conf, cbor_certificate, cert_len));
    EDHOC_CHECK_RET(edhoc_conf_load_cred_id(&conf, cred_id, cred_id_len));

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // load the ephemeral key (not necessary normally but here we set it for deterministic test behavior)
    EDHOC_CHECK_RET(edhoc_load_ephkey(&ctx, eph_key, eph_key_len));

    EDHOC_CHECK_RET(edhoc_session_preset_cidr(&ctx, cid, cid_len));

    if ((ret = edhoc_create_msg2(&ctx, msg1, msg1_len, NULL, 0, mbuf, sizeof(mbuf))) < EDHOC_SUCCESS) {
        goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int main(int argc, char **argv) {
    test_context_ptr ctx;
    uint8_t message_1[100], resp_ephkey[100], conn_id[4], resp_authkey[100], message_2[250], cbor_cert[200], cred_id[50];
    size_t msg1_len, resp_ephkey_len, conn_id_len, resp_authkey_len, msg2_len, cert_len, cred_id_len;

    memset(message_1, 0, sizeof(message_1));
    memset(message_2, 0, sizeof(message_2));
    memset(resp_ephkey, 0, sizeof(resp_ephkey));
    memset(resp_authkey, 0, sizeof(resp_authkey));
    memset(conn_id, 0, sizeof(conn_id));

    if (argc == 3) {
        if (strcmp(argv[1], "--responder") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            msg1_len = load_from_json_MESSAGE1(ctx, message_1, sizeof(message_1));
            resp_ephkey_len = load_from_json_RESP_EPHKEY(ctx, resp_ephkey, sizeof(resp_ephkey));
            resp_authkey_len = load_from_json_RESP_AUTHKEY(ctx, resp_authkey, sizeof(resp_authkey));
            conn_id_len = load_from_json_CONN_IDR(ctx, conn_id, sizeof(conn_id));
            msg2_len = load_from_json_MESSAGE2(ctx, message_2, sizeof(message_2));
            cert_len = load_from_json_RESP_CERT(ctx, cbor_cert, sizeof(cbor_cert));
            cred_id_len = load_from_json_RESP_X5T(ctx, cred_id, sizeof(cred_id));

            assert(test_message2_encoding(
                    resp_ephkey,
                    resp_ephkey_len,
                    resp_authkey,
                    resp_authkey_len,
                    conn_id,
                    conn_id_len,
                    message_1,
                    msg1_len,
                    cbor_cert,
                    cert_len,
                    cred_id,
                    cred_id_len,
                    message_2,
                    msg2_len) == EDHOC_SUCCESS);
        }
    }

    return 0;
}
