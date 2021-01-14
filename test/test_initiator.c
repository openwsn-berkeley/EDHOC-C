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
    int ret = EDHOC_SUCCESS;
    uint8_t mbuf[200];

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
    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_INITIATOR, NULL, NULL, NULL));
#endif

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // load the ephemeral key (not necessary normally but here we set it for deterministic test behavior)
    EDHOC_CHECK_RET(edhoc_load_ephkey(&ctx, eph_key, eph_key_len));

    EDHOC_CHECK_RET(edhoc_session_preset_cidi(&ctx, conn_id, conn_id_len));

    // create the first message
    assert(edhoc_create_msg1(&ctx, corr, m, suite, NULL, 0, mbuf, sizeof(mbuf)) == expected_len);
    assert(compare_arrays(mbuf, expected_msg, expected_len));

    exit:
    return ret;
}

int main(int argc, char **argv) {
    test_context_ptr ctx;
    uint8_t message_1[100], init_ephkey[100], conn_id[4];
    size_t msg1_len, init_ephkey_len, conn_id_len;
    int corr, method, selected;

    memset(message_1, 0, sizeof(message_1));
    memset(init_ephkey, 0, sizeof(init_ephkey));
    memset(conn_id, 0, sizeof(conn_id));

    if(argc == 3){
        if (strcmp(argv[1], "--initiator") == 0){
            if((ctx = load_json_test_file(argv[2])) == NULL){
                return EXIT_FAILURE;
            }

            load_from_json_CIPHERSUITE(ctx, &selected);
            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);

            msg1_len = load_from_json_MESSAGE1(ctx, message_1, sizeof(message_1));
            init_ephkey_len = load_from_json_INIT_EPHKEY(ctx, init_ephkey, sizeof(init_ephkey));
            conn_id_len = load_from_json_CONN_IDI(ctx, conn_id, sizeof(conn_id));

            assert(initiator_create_message1(
                    init_ephkey,
                    init_ephkey_len,
                    corr,
                    method,
                    conn_id,
                    conn_id_len,
                    selected,
                    message_1,
                    msg1_len) == EDHOC_SUCCESS);

            close_test(ctx);
        }
    }

    return EXIT_SUCCESS;
}
