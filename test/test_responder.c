#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <edhoc/edhoc.h>

#include "json.h"
#include "util.h"

int test_message2_encoding(
        const uint8_t *eph_key,
        size_t eph_key_len,
        const uint8_t *auth_key,
        size_t auth_key_len,
        const uint8_t *cid,
        size_t cid_len,
        const uint8_t *msg1,
        size_t msg1_len,
        uint8_t *cbor_certificate,
        size_t cert_len,
        uint8_t *cred_id,
        size_t cred_id_len,
        const uint8_t *expected_msg,
        size_t expected_len) {

    ssize_t ret;
    uint8_t mbuf[MESSAGE_2_SIZE];

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

    CHECK_TEST_RET_EQ(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                            mbedtls_entropy_func,
                                            &entropy,
                                            (const unsigned char *) pers,
                                            strlen(pers)), (long)0);


    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, mbedtls_entropy_func, &entropy, NULL), (long)0);
#elif defined(WOLFSSL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#endif

    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cborcert(&conf, cbor_certificate, cert_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cred_id(&conf, cred_id, cred_id_len), (long) 0);

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // load the ephemeral key (not necessary normally but here we set it for deterministic test behavior)
    CHECK_TEST_RET_EQ(edhoc_load_ephkey(&ctx, eph_key, eph_key_len), (long) 0);

    CHECK_TEST_RET_EQ(edhoc_session_preset_cidr(&ctx, cid, cid_len), (long) 0);

    CHECK_TEST_RET_EQ(edhoc_create_msg2(&ctx, msg1, msg1_len, mbuf, sizeof(mbuf)), expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(mbuf, expected_msg, expected_len), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int main(int argc, char **argv) {

    /* temporary buffers */
    ssize_t ret;
    test_context_ptr ctx;

    uint8_t m1[MESSAGE_1_SIZE];
    uint8_t resp_ephkey[EPHKEY_SIZE];
    uint8_t conn_id[CONN_ID_SIZE];
    uint8_t resp_authkey[AUTHKEY_SIZE];
    uint8_t message_2[MESSAGE_2_SIZE];
    uint8_t resp_cred[CRED_SIZE];
    uint8_t resp_cred_id[CRED_ID_SIZE];

    size_t msg1_len, resp_ephkey_len, conn_id_len, resp_authkey_len, msg2_len, cert_len, cred_id_len;

    /* test selection */
    ret = 0;

    if (argc == 3) {
        if (strcmp(argv[1], "--responder") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            resp_ephkey_len = load_from_json_RESP_EPHKEY(ctx, resp_ephkey, sizeof(resp_ephkey));
            resp_authkey_len = load_from_json_RESP_AUTHKEY(ctx, resp_authkey, sizeof(resp_authkey));
            conn_id_len = load_from_json_CONN_IDR(ctx, conn_id, sizeof(conn_id));
            msg2_len = load_from_json_MESSAGE2(ctx, message_2, sizeof(message_2));
            cert_len = load_from_json_RESP_CRED(ctx, resp_cred, sizeof(resp_cred));
            cred_id_len = load_from_json_RESP_CRED_ID(ctx, resp_cred_id, sizeof(resp_cred_id));

            ret = test_message2_encoding(resp_ephkey,
                                         resp_ephkey_len,
                                         resp_authkey,
                                         resp_authkey_len,
                                         conn_id,
                                         conn_id_len,
                                         m1,
                                         msg1_len,
                                         resp_cred,
                                         cert_len,
                                         resp_cred_id,
                                         cred_id_len,
                                         message_2,
                                         msg2_len);

            close_test(ctx);
        }
    }

    return ret;
}
