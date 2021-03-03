#include <assert.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <cipher_suites.h>

#include "util.h"
#include "json.h"


int test_create_msg1(cred_type_t cred_type,
                     const uint8_t *eph_key,
                     size_t eph_key_len,
                     corr_t corr,
                     uint8_t m,
                     const uint8_t *conn_id,
                     size_t conn_id_len,
                     uint8_t suite,
                     const uint8_t *expected_msg,
                     size_t expected_len) {

    (void) cred_type;
    ssize_t ret;
    uint8_t mbuf[MESSAGE_1_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL), (long) 0);

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

int test_create_msg2(cred_type_t cred_type,
                     const uint8_t *eph_key,
                     size_t eph_key_len,
                     const uint8_t *auth_key,
                     size_t auth_key_len,
                     const uint8_t *cid,
                     size_t cid_len,
                     const uint8_t *msg1,
                     size_t msg1_len,
                     uint8_t *credentials,
                     size_t cred_len,
                     uint8_t *cred_id,
                     size_t cred_id_len,
                     cred_id_type_t cred_id_type,
                     const uint8_t *expected_msg,
                     size_t expected_len) {

    ssize_t ret;
    uint8_t mbuf[MESSAGE_2_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    rpk_t auth_pub_key;
    cbor_cert_t auth_cbor_cert;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, NULL, NULL), (long) 0);

    if (cred_type == CRED_TYPE_CBOR_CERT) {
        edhoc_cred_cbor_cert_init(&auth_cbor_cert);
        CHECK_TEST_RET_EQ(edhoc_cred_load_cbor_cert(&auth_cbor_cert, credentials, cred_len), (long) 0);
        edhoc_conf_load_credentials(&conf, CRED_TYPE_CBOR_CERT, &auth_cbor_cert, NULL);
    } else {
        edhoc_cred_pub_key_init(&auth_pub_key);
        CHECK_TEST_RET_EQ(edhoc_cred_load_pub_key(&auth_pub_key, credentials, cred_len), (long) 0);
        edhoc_conf_load_credentials(&conf, CRED_TYPE_RPK, &auth_pub_key, NULL);
    }

    CHECK_TEST_RET_EQ(edhoc_conf_load_cred_id(&conf, cred_id, cred_id_type, cred_id_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);

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

int test_create_msg3(cred_type_t cred_type,
                     const uint8_t *eph_key,
                     size_t eph_key_len,
                     const uint8_t *auth_key,
                     size_t auth_key_len,
                     corr_t corr,
                     uint8_t m,
                     const uint8_t *conn_id,
                     size_t conn_id_len,
                     uint8_t suite,
                     uint8_t *credentials,
                     size_t cred_len,
                     uint8_t *cred_id,
                     size_t cred_id_len,
                     cred_id_type_t cred_id_type,
                     const uint8_t *incoming_msg2,
                     size_t incoming_msg2_len,
                     const uint8_t *expected_msg,
                     size_t expected_len) {
    ssize_t ret;
    uint8_t mbuf[MESSAGE_3_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    rpk_t auth_pub_key;
    cbor_cert_t auth_cbor_cert;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    CHECK_TEST_RET_EQ(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL), (long) 0);

    if (cred_type == CRED_TYPE_CBOR_CERT) {
        edhoc_cred_cbor_cert_init(&auth_cbor_cert);
        CHECK_TEST_RET_EQ(edhoc_cred_load_cbor_cert(&auth_cbor_cert, credentials, cred_len), (long) 0);
        edhoc_conf_load_credentials(&conf, CRED_TYPE_CBOR_CERT, &auth_cbor_cert, NULL);
    } else {
        edhoc_cred_pub_key_init(&auth_pub_key);
        CHECK_TEST_RET_EQ(edhoc_cred_load_pub_key(&auth_pub_key, credentials, cred_len), (long) 0);
        edhoc_conf_load_credentials(&conf, CRED_TYPE_RPK, &auth_pub_key, NULL);
    }

    CHECK_TEST_RET_EQ(edhoc_conf_load_cred_id(&conf, cred_id, cred_id_type, cred_id_len), (long) 0);
    CHECK_TEST_RET_EQ(edhoc_conf_load_authkey(&conf, auth_key, auth_key_len), (long) 0);

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
    test_edhoc_ctx ctx;

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

    int corr, method, selected, cred_type;
    cred_id_type_t cred_id_type;

    /* test selection */
    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--create-msg1") == 0) {
            if ((ctx = load_json_edhoc_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            assert(load_from_json_CIPHERSUITE(ctx, &selected) == SUCCESS);
            assert(load_from_json_CORR(ctx, &corr) == SUCCESS);
            assert(load_from_json_METHOD(ctx, &method) == SUCCESS);
            load_from_json_RESP_CREDTYPE(ctx, &cred_type);

            m1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            ephkey_len = load_from_json_INIT_EPHKEY(ctx, ephkey, sizeof(ephkey));
            cid_len = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));

            assert(m1_len >= 0);
            assert(ephkey_len >= 0);
            assert(cid_len >= 0);

            ret = test_create_msg1(cred_type, ephkey, ephkey_len, corr, method, cid, cid_len, selected, m1, m1_len);

            close_edhoc_test(ctx);

        } else if (strcmp(argv[1], "--create-msg2") == 0) {
            if ((ctx = load_json_edhoc_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            m1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            ephkey_len = load_from_json_RESP_EPHKEY(ctx, ephkey, sizeof(ephkey));
            authkey_len = load_from_json_RESP_AUTHKEY(ctx, authkey, sizeof(authkey));
            cid_len = load_from_json_CONN_IDR(ctx, cid, sizeof(cid));
            m2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            cred_len = load_from_json_RESP_CRED(ctx, cred, sizeof(cred));
            cred_id_len = load_from_json_RESP_CRED_ID(ctx, cred_id, sizeof(cred_id));
            load_from_json_RESP_CREDTYPE(ctx, &cred_type);
            load_from_json_RESP_CREDID_TYPE(ctx, (int *) &cred_id_type);

            ret = test_create_msg2(cred_type,
                                   ephkey,
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
                                   cred_id_type,
                                   m2,
                                   m2_len);

            close_edhoc_test(ctx);

        } else if (strcmp(argv[1], "--create-msg3") == 0) {
            if ((ctx = load_json_edhoc_test_file(argv[2])) == NULL) {
                return EXIT_FAILURE;
            }

            load_from_json_INIT_CREDTYPE(ctx, &cred_type);
            load_from_json_INIT_CREDID_TYPE(ctx, (int *) &cred_id_type);
            load_from_json_CIPHERSUITE(ctx, &selected);
            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);

            ephkey_len = load_from_json_INIT_EPHKEY(ctx, ephkey, sizeof(ephkey));
            cid_len = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));
            m2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            authkey_len = load_from_json_INIT_AUTHKEY(ctx, authkey, sizeof(authkey));
            cred_len = load_from_json_INIT_CRED(ctx, cred, sizeof(cred));
            cred_id_len = load_from_json_INIT_CRED_ID(ctx, cred_id, sizeof(cred_id));
            m3_len = load_from_json_MESSAGE3(ctx, m3, sizeof(m3));

            ret = test_create_msg3(cred_type,
                                   ephkey,
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
                                   cred_id_type,
                                   m2,
                                   m2_len,
                                   m3,
                                   m3_len);

            close_edhoc_test(ctx);
        }
    }

    return ret;
}
