#include <assert.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <cipher_suites.h>

#include "util.h"
#include "json.h"

#include "process.h"


int test_create_msg1(
        const uint8_t *eph_key,
        size_t eph_key_len,
        corr_t corr,
        uint8_t m,
        const uint8_t *conn_id,
        size_t conn_id_len,
        uint8_t suite,
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

    EDHOC_CHECK_SUCCESS(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_SUCCESS(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, mbedtls_entropy_func, &entropy, NULL));
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

int test_create_msg2(
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
#elif defined(HACL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#else
#error "No crypto backend selected"
#endif

    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cbor_cert(&conf, cbor_certificate, cert_len), (long) 0);
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

int test_create_msg3(const uint8_t *eph_key,
                     size_t eph_key_len,
                     const uint8_t *auth_key,
                     size_t auth_key_len,
                     corr_t corr,
                     uint8_t m,
                     const uint8_t *conn_id,
                     size_t conn_id_len,
                     uint8_t suite,
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

    EDHOC_CHECK_SUCCESS(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_SUCCESS(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, mbedtls_entropy_func, &entropy, NULL));
#elif defined(WOLFSSL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#elif defined(HACL)
    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL, NULL, NULL, NULL), (long) 0);
#else
#error "No crypto backend selected"
#endif

    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_cbor_cert(&conf, cbor_certificate, cert_len), (long) 0);
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

    uint8_t m1[MESSAGE_1_SIZE];
    ssize_t m1_len;
    uint8_t m2[MESSAGE_2_SIZE];
    ssize_t m2_len;
    uint8_t m3[MESSAGE_3_SIZE];
    ssize_t m3_len;

    uint8_t ephkey[EPHKEY_SIZE];
    ssize_t ephkey_len;
    uint8_t authkey[AUTHKEY_SIZE];
    ssize_t authkey_len;
    uint8_t cred[CRED_SIZE];
    ssize_t cred_len;
    uint8_t cred_id[CRED_ID_SIZE];
    ssize_t cred_id_len;
    uint8_t cid[CONN_ID_SIZE];
    ssize_t cid_len;

    int corr, method, selected;

    /* test selection */
    ret = 0;

    if (argc == 3) {
        if (strcmp(argv[1], "--create-msg1") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            assert(load_from_json_CIPHERSUITE(ctx, &selected) == SUCCESS);
            assert(load_from_json_CORR(ctx, &corr) == SUCCESS);
            assert(load_from_json_METHOD(ctx, &method) == SUCCESS);

            m1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            ephkey_len = load_from_json_INIT_EPHKEY(ctx, ephkey, sizeof(ephkey));
            cid_len = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));

            assert(m1_len >= 0);
            assert(ephkey_len >= 0);
            assert(cid_len >= 0);

            ret = test_create_msg1(ephkey, ephkey_len, corr, method, cid, cid_len, selected, m1, m1_len);

            close_test(ctx);

        } else if (strcmp(argv[1], "--create-msg2") == 0) {
            if ((ctx = load_json_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            m1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            ephkey_len = load_from_json_RESP_EPHKEY(ctx, ephkey, sizeof(ephkey));
            authkey_len = load_from_json_RESP_AUTHKEY(ctx, authkey, sizeof(authkey));
            cid_len = load_from_json_CONN_IDR(ctx, cid, sizeof(cid));
            m2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            cred_len = load_from_json_RESP_CRED(ctx, cred, sizeof(cred));
            cred_id_len = load_from_json_RESP_CRED_ID(ctx, cred_id, sizeof(cred_id));

            ret = test_create_msg2(ephkey,
                                   ephkey_len,
                                   authkey,
                                   authkey_len,
                                   cid,
                                   cid_len,
                                   m1,
                                   m1_len,
                                   cred,
                                   cred_len,
                                   cred_id,
                                   cred_id_len,
                                   m2,
                                   m2_len);

            close_test(ctx);
        }

    } else if (strcmp(argv[1], "--create-msg3") == 0) {
        if ((ctx = load_json_test_file(argv[2])) == NULL) {
            return EXIT_FAILURE;
        }

        assert(load_from_json_CIPHERSUITE(ctx, &selected) == SUCCESS);
        assert(load_from_json_CORR(ctx, &corr) == SUCCESS);
        assert(load_from_json_METHOD(ctx, &method) == SUCCESS);

        ephkey_len = load_from_json_INIT_EPHKEY(ctx, ephkey, sizeof(ephkey));
        cid_len = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));
        m2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
        authkey_len = load_from_json_INIT_AUTHKEY(ctx, authkey, sizeof(authkey));
        cred_len = load_from_json_INIT_CRED(ctx, cred, sizeof(cred));
        cred_id_len = load_from_json_INIT_CRED_ID(ctx, cred_id, sizeof(cred_id));
        m3_len = load_from_json_MESSAGE3(ctx, m3, sizeof(m3));

        ret = test_create_msg3(ephkey,
                               ephkey_len,
                               authkey,
                               authkey_len,
                               corr,
                               method,
                               cid,
                               cid_len,
                               selected,
                               cred,
                               cred_len,
                               cred_id,
                               cred_id_len,
                               m2,
                               m2_len,
                               m3,
                               m3_len);

        close_test(ctx);
    }

    return ret;
}
