#include <edhoc/edhoc.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "json.h"

int initiator_create_message1(
        const uint8_t *eph_key,
        size_t eph_key_len,
        corr_t corr,
        method_t m,
        const uint8_t *conn_id,
        size_t conn_id_len,
        cipher_suite_t suite,
        const uint8_t *expected_msg,
        size_t expected_len) {

    ssize_t ret;
    uint8_t mbuf[MESSAGE_1_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

#if defined(MBEDTLS)
    // create a strong randomness source
    char *pers = "edhoc_initiator";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    EDHOC_CHECK_RET(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, mbedtls_entropy_func, &entropy, NULL));
#elif defined(WOLFSSL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#endif

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // load the ephemeral key (not necessary normally but here we set it for deterministic test behavior)
    CHECK_TEST_RET_EQ(edhoc_load_ephkey(&ctx, eph_key, eph_key_len), (long) 0);

    CHECK_TEST_RET_EQ(edhoc_session_preset_cidi(&ctx, conn_id, conn_id_len), (long) 0);

    // create the first message
    CHECK_TEST_RET_EQ(edhoc_create_msg1(&ctx, corr, m, suite, mbuf, sizeof(mbuf)), (long) expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(mbuf, expected_msg, expected_len), (long) 0);

    exit:
    return ret;
}

int initiator_create_message3(const uint8_t *eph_key,
                              size_t eph_key_len,
                              const uint8_t *auth_key,
                              size_t auth_key_len,
                              corr_t corr,
                              method_t m,
                              const uint8_t *conn_id,
                              size_t conn_id_len,
                              cipher_suite_t suite,
                              uint8_t *cbor_certificate,
                              size_t cert_len,
                              uint8_t *cred_id,
                              size_t cred_id_len,
                              const uint8_t *incoming_msg2,
                              size_t incoming_msg2_len,
                              const uint8_t *expected_msg,
                              size_t expected_len) {
    ssize_t ret;
    uint8_t mbuf[MESSAGE_3_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

#if defined(MBEDTLS)
    // create a strong randomness source
    char *pers = "edhoc_initiator";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    EDHOC_CHECK_RET(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, mbedtls_entropy_func, &entropy, NULL));
#elif defined(WOLFSSL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#endif

    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cborcert(&conf, cbor_certificate, cert_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cred_id(&conf, cred_id, cred_id_len), (long) 0);

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // load the ephemeral key (not necessary normally but here we set it for deterministic test behavior)
    CHECK_TEST_RET_EQ(edhoc_load_ephkey(&ctx, eph_key, eph_key_len), (long) 0);

    CHECK_TEST_RET_EQ(edhoc_session_preset_cidi(&ctx, conn_id, conn_id_len), (long) 0);

    CHECK_TEST_RET_GT(edhoc_create_msg1(&ctx, corr, m, suite, mbuf, sizeof(mbuf)), 0);
    CHECK_TEST_RET_EQ(edhoc_create_msg3(&ctx, incoming_msg2, incoming_msg2_len, mbuf, sizeof(mbuf)), expected_len);

    CHECK_TEST_RET_EQ(compare_arrays(mbuf, expected_msg, expected_len), (long) 0);

    exit:
    return ret;
}

int main(int argc, char **argv) {

    /* buffers */
    int ret;
    test_context_ptr ctx;

    uint8_t message_1[MESSAGE_1_SIZE];
    uint8_t message_2[MESSAGE_2_SIZE];
    uint8_t message_3[MESSAGE_3_SIZE];

    uint8_t init_ephkey[EPHKEY_SIZE];
    uint8_t init_authkey[AUTHKEY_SIZE];
    uint8_t init_cred[CRED_SIZE];
    uint8_t init_cred_id[CRED_ID_SIZE];
    uint8_t init_cid[CONN_ID_SIZE];

    int corr, method, selected;
    ssize_t m1_len, init_ephkey_len, init_cid_len, m2_len, init_authkey_len, init_cred_len, init_cred_id_len, m3_len;

    /* test selection */
    ret = 0;

    if (argc == 3) {
        if (strcmp(argv[1], "--initiator-msg1") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            assert(load_from_json_CIPHERSUITE(ctx, &selected) == SUCCESS);
            assert(load_from_json_CORR(ctx, &corr) == SUCCESS);
            assert(load_from_json_METHOD(ctx, &method) == SUCCESS);

            m1_len = load_from_json_MESSAGE1(ctx, message_1, sizeof(message_1));
            init_ephkey_len = load_from_json_INIT_EPHKEY(ctx, init_ephkey, sizeof(init_ephkey));
            init_cid_len = load_from_json_CONN_IDI(ctx, init_cid, sizeof(init_cid));

            assert(m1_len >= 0);
            assert(init_ephkey_len >= 0);
            assert(init_cid_len >= 0);

            ret = initiator_create_message1(init_ephkey,
                                            init_ephkey_len,
                                            corr,
                                            method,
                                            init_cid,
                                            init_cid_len,
                                            selected,
                                            message_1,
                                            m1_len);

            close_test(ctx);

        } else if (strcmp(argv[1], "--initiator-msg3") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            assert(load_from_json_CIPHERSUITE(ctx, &selected) == SUCCESS);
            assert(load_from_json_CORR(ctx, &corr) == SUCCESS);
            assert(load_from_json_METHOD(ctx, &method) == SUCCESS);

            init_ephkey_len = load_from_json_INIT_EPHKEY(ctx, init_ephkey, sizeof(init_ephkey));
            init_cid_len = load_from_json_CONN_IDI(ctx, init_cid, sizeof(init_cid));
            m2_len = load_from_json_MESSAGE2(ctx, message_2, sizeof(message_2));
            init_authkey_len = load_from_json_INIT_AUTHKEY(ctx, init_authkey, sizeof(init_authkey));
            init_cred_len = load_from_json_INIT_CRED(ctx, init_cred, sizeof(init_cred));
            init_cred_id_len = load_from_json_INIT_CRED_ID(ctx, init_cred_id, sizeof(init_cred_id));
            m3_len = load_from_json_MESSAGE3(ctx, message_3, sizeof(message_3));

            ret = initiator_create_message3(init_ephkey,
                                            init_ephkey_len,
                                            init_authkey,
                                            init_authkey_len,
                                            corr,
                                            method,
                                            init_cid,
                                            init_cid_len,
                                            selected,
                                            init_cred,
                                            init_cred_len,
                                            init_cred_id,
                                            init_cred_id_len,
                                            message_2,
                                            m2_len,
                                            message_3,
                                            m3_len);

            close_test(ctx);
        }
    }

    return ret;
}
