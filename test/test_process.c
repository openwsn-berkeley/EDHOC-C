#include <string.h>
#include <mbedtls/x509_crt.h>

#include "edhoc/edhoc.h"
#include "edhoc/creddb.h"

#include "util.h"
#include "json.h"

#if defined(WOLFSSL)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#elif defined(HACL)

#define HASH_INPUT_BLEN     (256)

typedef struct hacl_Sha256 hacl_Sha256;

struct hacl_Sha256 {
    uint16_t fillLevel;
    uint8_t buffer[HASH_INPUT_BLEN];
};
#elif defined(TINYCRYPT)
#include "crypto/tinycrypt/sha256.h"
#endif



int test_create_msg1(corr_t corr,
                     method_t m,
                     cipher_suite_id_t id,
                     const uint8_t *cid,
                     size_t cidLen,
                     const uint8_t *ephKey,
                     size_t ephKeyLen,
                     const uint8_t *expected,
                     size_t expectedLen) {

    int ret;
    uint8_t msg1[MESSAGE_1_SIZE];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

#if defined(WOLFSSL)
    wc_Sha256 thCtx;
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  thCtx;
#endif

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    // to get deterministic test results
    TEST_CHECK_EQUAL((long) edhoc_load_ephkey(&ctx, ephKey, ephKeyLen), (long) EDHOC_SUCCESS);
    TEST_CHECK_EQUAL((long) edhoc_session_preset_cidi(&ctx, cid, cidLen), (long) 0);

    TEST_CHECK_EQUAL(edhoc_create_msg1(&ctx, corr, m, id, msg1, sizeof(msg1)), (long) expectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg1, expected, expectedLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int test_create_msg2(cred_type_t credType,
                     const uint8_t *cborEphKey,
                     size_t ephKeyLen,
                     const uint8_t *cborAuthKey,
                     size_t authKeyLen,
                     const uint8_t *cid,
                     size_t cidLen,
                     const uint8_t *msg1,
                     size_t msg1Len,
                     uint8_t *credentials,
                     size_t credLen,
                     uint8_t *credId,
                     size_t credIdLen,
                     const uint8_t *expected,
                     size_t expectedLen) {
    ssize_t ret;
    uint8_t msg2[MESSAGE_2_SIZE];

    cred_id_t credIdCtx;
    c509_t c509Ctx;
    mbedtls_x509_crt x509Ctx;
    rpk_t rpkCtx;

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cose_key_t authKey;
#if defined(WOLFSSL)
    wc_Sha256 thCtx;
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  thCtx;
#endif

    cose_key_init(&authKey);

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    TEST_CHECK_EQUAL((long) cose_key_from_cbor(&authKey, cborAuthKey, authKeyLen), (long) EDHOC_SUCCESS);

    // for deterministic tests
    TEST_CHECK_EQUAL((long) edhoc_load_ephkey(&ctx, cborEphKey, ephKeyLen), (long) EDHOC_SUCCESS);
    TEST_CHECK_EQUAL((long) edhoc_session_preset_cidr(&ctx, cid, cidLen), (long) EDHOC_SUCCESS);

    cred_id_init(&credIdCtx);
    cred_id_from_cbor(&credIdCtx, credId, credIdLen);

    if (credType == CRED_TYPE_CBOR_CERT) {
        cred_c509_init(&c509Ctx);
        cred_c509_from_cbor(&c509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &c509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_DER_CERT) {
        cred_x509_init(&x509Ctx);
        cred_x509_from_der(&x509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &x509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_RPK) {
        cred_rpk_init(&rpkCtx);
        cred_rpk_from_cbor(&rpkCtx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &rpkCtx, &credIdCtx, f_remote_creds);
    } else {
        ret = EDHOC_ERR_INVALID_CRED;
        goto exit;
    }

    edhoc_conf_setup_role(&conf, EDHOC_IS_RESPONDER);
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    TEST_CHECK_EQUAL(edhoc_create_msg2(&ctx, msg1, msg1Len, msg2, MESSAGE_2_SIZE), expectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg2, expected, expectedLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int test_create_msg3(corr_t corr,
                     method_t m,
                     cipher_suite_id_t id,
                     cred_type_t credType,
                     const uint8_t *cborEphKey,
                     size_t ephKeyLen,
                     const uint8_t *cborAuthKey,
                     size_t authKeyLen,
                     const uint8_t *cid,
                     size_t cidLen,
                     const uint8_t *msg2,
                     size_t msg2Len,
                     uint8_t *credentials,
                     size_t credLen,
                     uint8_t *credId,
                     size_t credIdLen,
                     const uint8_t *m1Expected,
                     size_t m1ExpectedLen,
                     const uint8_t *m3Expected,
                     size_t m3ExpectedLen) {
    ssize_t ret;
    uint8_t msg1[MESSAGE_1_SIZE];
    uint8_t msg3[MESSAGE_3_SIZE];

    cred_id_t credIdCtx;
    c509_t c509Ctx;
    mbedtls_x509_crt x509Ctx;
    rpk_t rpkCtx;

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cose_key_t authKey;
#if defined(WOLFSSL)
    wc_Sha256 thCtx;
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  thCtx;
#endif

    cose_key_init(&authKey);

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    TEST_CHECK_EQUAL((long) cose_key_from_cbor(&authKey, cborAuthKey, authKeyLen), (long) EDHOC_SUCCESS);

    // for deterministic tests
    TEST_CHECK_EQUAL((long) edhoc_load_ephkey(&ctx, cborEphKey, ephKeyLen), (long) EDHOC_SUCCESS);
    TEST_CHECK_EQUAL((long) edhoc_session_preset_cidi(&ctx, cid, cidLen), (long) EDHOC_SUCCESS);

    cred_id_init(&credIdCtx);
    cred_id_from_cbor(&credIdCtx, credId, credIdLen);

    if (credType == CRED_TYPE_CBOR_CERT) {
        cred_c509_init(&c509Ctx);
        cred_c509_from_cbor(&c509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &c509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_DER_CERT) {
        cred_x509_init(&x509Ctx);
        cred_x509_from_der(&x509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &x509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_RPK) {
        cred_rpk_init(&rpkCtx);
        cred_rpk_from_cbor(&rpkCtx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &rpkCtx, &credIdCtx, f_remote_creds);
    } else {
        ret = EDHOC_ERR_INVALID_CRED;
        goto exit;
    }

    edhoc_conf_setup_role(&conf, EDHOC_IS_INITIATOR);
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    TEST_CHECK_EQUAL(edhoc_create_msg1(&ctx, corr, m, id, msg1, sizeof(msg1)), (long) m1ExpectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg1, m1Expected, m1ExpectedLen), (long) 0);

    TEST_CHECK_EQUAL(edhoc_create_msg3(&ctx, msg2, msg2Len, msg3, MESSAGE_3_SIZE), m3ExpectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg3, m3Expected, m3ExpectedLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int test_resp_finalize(cred_type_t credType,
                       const uint8_t *cborEphKey,
                       size_t ephKeyLen,
                       const uint8_t *cborAuthKey,
                       size_t authKeyLen,
                       const uint8_t *cid,
                       size_t cidLen,
                       const uint8_t *msg1,
                       size_t msg1Len,
                       const uint8_t *msg3,
                       size_t msg3Len,
                       uint8_t *credentials,
                       size_t credLen,
                       uint8_t *credId,
                       size_t credIdLen,
                       const uint8_t *m2Expected,
                       size_t m2ExpectedLen,
                       bool sendMsg4,
                       const uint8_t *m4Expected,
                       size_t m4ExpectedLen) {
    ssize_t ret;
    uint8_t msg2[MESSAGE_2_SIZE];
    uint8_t msg4[MESSAGE_4_SIZE];

    cred_id_t credIdCtx;
    c509_t c509Ctx;
    mbedtls_x509_crt x509Ctx;
    rpk_t rpkCtx;

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cose_key_t authKey;
#if defined(WOLFSSL)
    wc_Sha256 thCtx;
#elif defined(HACL)
    hacl_Sha256 thCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  thCtx;
#endif

    cose_key_init(&authKey);

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    TEST_CHECK_EQUAL((long) cose_key_from_cbor(&authKey, cborAuthKey, authKeyLen), (long) EDHOC_SUCCESS);

    // for deterministic tests
    TEST_CHECK_EQUAL((long) edhoc_load_ephkey(&ctx, cborEphKey, ephKeyLen), (long) EDHOC_SUCCESS);
    TEST_CHECK_EQUAL((long) edhoc_session_preset_cidr(&ctx, cid, cidLen), (long) EDHOC_SUCCESS);

    cred_id_init(&credIdCtx);
    cred_id_from_cbor(&credIdCtx, credId, credIdLen);

    if (credType == CRED_TYPE_CBOR_CERT) {
        cred_c509_init(&c509Ctx);
        cred_c509_from_cbor(&c509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &c509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_DER_CERT) {
        cred_x509_init(&x509Ctx);
        cred_x509_from_der(&x509Ctx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &x509Ctx, &credIdCtx, f_remote_creds);
    } else if (credType == CRED_TYPE_RPK) {
        cred_rpk_init(&rpkCtx);
        cred_rpk_from_cbor(&rpkCtx, credentials, credLen);
        edhoc_conf_setup_credentials(&conf, &authKey, credType, &rpkCtx, &credIdCtx, f_remote_creds);
    } else {
        ret = EDHOC_ERR_INVALID_CRED;
        goto exit;
    }

    edhoc_conf_setup_role(&conf, EDHOC_IS_RESPONDER);
    edhoc_ctx_setup(&ctx, &conf, &thCtx);

    TEST_CHECK_EQUAL(edhoc_create_msg2(&ctx, msg1, msg1Len, msg2, MESSAGE_2_SIZE), m2ExpectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg2, m2Expected, m2ExpectedLen), (long) 0);

    TEST_CHECK_EQUAL(edhoc_resp_finalize(&ctx, msg3, msg3Len, sendMsg4, msg4, MESSAGE_4_SIZE), m4ExpectedLen);
    TEST_CHECK_EQUAL((long) memcmp(msg4, m4Expected, m4ExpectedLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int main(int argc, char **argv) {
    int ret;
    test_edhoc_ctx ctx;

    int corr, selected, method, credType;

    uint8_t msg1[MESSAGE_1_SIZE];
    size_t msg1Len;

    uint8_t msg2[MESSAGE_2_SIZE];
    size_t msg2Len;

    uint8_t msg3[MESSAGE_3_SIZE];
    size_t msg3Len;

    uint8_t ephKey[EPHKEY_SIZE];
    size_t ephKeyLen;

    uint8_t authKey[EPHKEY_SIZE];
    size_t authKeyLen;

    uint8_t cred[CRED_SIZE];
    size_t credLen;

    uint8_t credId[CRED_SIZE];
    size_t credIdLen;

    uint8_t cid[CONN_ID_SIZE];
    size_t cidLen;

    /* test selection */

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--create-msg1") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);
            load_from_json_CIPHERSUITE(ctx, &selected);

            cidLen = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));
            ephKeyLen = load_from_json_INIT_EPHKEY(ctx, ephKey, sizeof(ephKey));
            msg1Len = load_from_json_MESSAGE1(ctx, msg1, sizeof(msg1));

            ret = test_create_msg1(corr, method, selected, cid, cidLen, ephKey, ephKeyLen, msg1, msg1Len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--create-msg2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            msg1Len = load_from_json_MESSAGE1(ctx, msg1, sizeof(msg1));
            ephKeyLen = load_from_json_RESP_EPHKEY(ctx, ephKey, sizeof(ephKey));
            authKeyLen = load_from_json_RESP_AUTHKEY(ctx, authKey, sizeof(authKey));
            cidLen = load_from_json_CONN_IDR(ctx, cid, sizeof(cid));
            msg2Len = load_from_json_MESSAGE2(ctx, msg2, sizeof(msg2));
            credLen = load_from_json_RESP_CRED(ctx, cred, sizeof(cred));
            credIdLen = load_from_json_RESP_CRED_ID(ctx, credId, sizeof(credId));
            load_from_json_RESP_CREDTYPE(ctx, &credType);

            ret = test_create_msg2(credType,
                                   ephKey,
                                   ephKeyLen,
                                   authKey,
                                   authKeyLen,
                                   cid,
                                   cidLen,
                                   msg1,
                                   msg1Len,
                                   cred,
                                   credLen,
                                   credId,
                                   credIdLen,
                                   msg2,
                                   msg2Len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--create-msg3") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);
            load_from_json_CIPHERSUITE(ctx, &selected);

            msg1Len = load_from_json_MESSAGE1(ctx, msg1, sizeof(msg1));
            ephKeyLen = load_from_json_INIT_EPHKEY(ctx, ephKey, sizeof(ephKey));
            authKeyLen = load_from_json_INIT_AUTHKEY(ctx, authKey, sizeof(authKey));
            cidLen = load_from_json_CONN_IDI(ctx, cid, sizeof(cid));
            msg2Len = load_from_json_MESSAGE2(ctx, msg2, sizeof(msg2));
            credLen = load_from_json_INIT_CRED(ctx, cred, sizeof(cred));
            credIdLen = load_from_json_INIT_CRED_ID(ctx, credId, sizeof(credId));
            msg3Len = load_from_json_MESSAGE3(ctx, msg3, sizeof(msg3));
            load_from_json_INIT_CREDTYPE(ctx, &credType);

            ret = test_create_msg3(corr,
                                   method,
                                   selected,
                                   credType,
                                   ephKey,
                                   ephKeyLen,
                                   authKey,
                                   authKeyLen,
                                   cid,
                                   cidLen,
                                   msg2,
                                   msg2Len,
                                   cred,
                                   credLen,
                                   credId,
                                   credIdLen,
                                   msg1,
                                   msg1Len,
                                   msg3,
                                   msg3Len);


            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--finalize-responder") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            msg1Len = load_from_json_MESSAGE1(ctx, msg1, sizeof(msg1));
            ephKeyLen = load_from_json_RESP_EPHKEY(ctx, ephKey, sizeof(ephKey));
            authKeyLen = load_from_json_RESP_AUTHKEY(ctx, authKey, sizeof(authKey));
            cidLen = load_from_json_CONN_IDR(ctx, cid, sizeof(cid));
            msg2Len = load_from_json_MESSAGE2(ctx, msg2, sizeof(msg2));
            credLen = load_from_json_RESP_CRED(ctx, cred, sizeof(cred));
            credIdLen = load_from_json_RESP_CRED_ID(ctx, credId, sizeof(credId));
            msg3Len = load_from_json_MESSAGE3(ctx, msg3, sizeof(msg3));
            load_from_json_RESP_CREDTYPE(ctx, &credType);

            ret = test_resp_finalize(credType,
                                     ephKey,
                                     ephKeyLen,
                                     authKey,
                                     authKeyLen,
                                     cid,
                                     cidLen,
                                     msg1,
                                     msg1Len,
                                     msg3,
                                     msg3Len,
                                     cred,
                                     credLen,
                                     credId,
                                     credIdLen,
                                     msg2,
                                     msg2Len,
                                     false,
                                     NULL,
                                     0);

            close_edhoc_test(ctx);

        }
    }

    return ret;
}
