#include <string.h>
#include <format.h>

#include "edhoc/edhoc.h"
#include "ciphersuites.h"

#include "json.h"
#include "util.h"

int test_oscore_master_secret(int cipherSuite,
                              const uint8_t *prk4x3m,
                              size_t prk4x3mLen,
                              const uint8_t *th4,
                              size_t th4Len,
                              const uint8_t *oscoreSecretInfo,
                              size_t oscoreSecretInfoLen,
                              const uint8_t *oscoreSecret,
                              size_t oscoreSecretLen) {
    int ret;

    ssize_t len;
    uint8_t out[100];
    uint8_t infoBuf[100];
    const char *label = "OSCORE Master Secret";

    edhoc_ctx_t ctx;
    const cipher_suite_t *suite = NULL;
    const cose_aead_t *aeadCipher = NULL;

    edhoc_ctx_init(&ctx);

    ctx.session.cipherSuiteID = cipherSuite;

    memcpy(ctx.session.prk4x3m, prk4x3m, prk4x3mLen);
    memcpy(ctx.session.th4, th4, th4Len);

    suite = edhoc_cipher_suite_from_id(cipherSuite);

    aeadCipher = cose_algo_get_aead_info(suite->appAeadCipher);

    len = format_info_encode(aeadCipher->id, ctx.session.th4, label, aeadCipher->keyLength, infoBuf, sizeof(infoBuf));
    TEST_CHECK_EQUAL(len, oscoreSecretInfoLen);
    TEST_CHECK_EQUAL(compare_arrays(oscoreSecretInfo, infoBuf, oscoreSecretLen), (long) 0);

    TEST_CHECK_EQUAL((long) edhoc_exporter(&ctx, label, aeadCipher->keyLength, out, sizeof(out)), (long) 0);
    TEST_CHECK_EQUAL(compare_arrays(oscoreSecret, out, oscoreSecretLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}


int test_oscore_master_salt(int cipherSuite,
                            const uint8_t *prk4x3m,
                            size_t prk4x3mLen,
                            const uint8_t *th4,
                            size_t th4Len,
                            const uint8_t *oscoreSaltInfo,
                            size_t oscoreSaltInfoLen,
                            const uint8_t *oscoreSalt,
                            size_t oscoreSaltLen) {
    int ret;

    ssize_t len;
    uint8_t out[100];
    uint8_t infoBuf[100];
    const char *label = "OSCORE Master Salt";

    edhoc_ctx_t ctx;
    const cipher_suite_t *suite = NULL;
    const cose_aead_t *aeadCipher = NULL;

    edhoc_ctx_init(&ctx);

    ctx.session.cipherSuiteID = cipherSuite;

    memcpy(ctx.session.prk4x3m, prk4x3m, prk4x3mLen);
    memcpy(ctx.session.th4, th4, th4Len);

    suite = edhoc_cipher_suite_from_id(cipherSuite);

    aeadCipher = cose_algo_get_aead_info(suite->appAeadCipher);

    len = format_info_encode(aeadCipher->id, ctx.session.th4, label, 8, infoBuf, sizeof(infoBuf));
    TEST_CHECK_EQUAL(len, oscoreSaltInfoLen);
    TEST_CHECK_EQUAL(compare_arrays(oscoreSaltInfo, infoBuf, oscoreSaltLen), (long) 0);

    TEST_CHECK_EQUAL((long) edhoc_exporter(&ctx, label, 8, out, sizeof(out)), (long) 0);
    TEST_CHECK_EQUAL(compare_arrays(oscoreSalt, out, oscoreSaltLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int main(int argc, char **argv) {
    int ret;
    test_edhoc_ctx ctx;
    int cipherSuite;

    uint8_t th4[TH_SIZE];
    ssize_t th4Len;

    uint8_t prk4x3m[SECRET_SIZE];
    ssize_t prk4x3mLen;

    uint8_t infoOscoreSecret[INFO_SIZE];
    ssize_t infoOscoreSecretLen;

    uint8_t oscoreSecret[SECRET_SIZE];
    ssize_t oscoreSecretLen;

    uint8_t infoOscoreSalt[INFO_SIZE];
    ssize_t infoOscoreSaltLen;

    uint8_t oscoreSalt[SECRET_SIZE];
    ssize_t oscoreSaltLen;

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--export-secret") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, &cipherSuite);

            th4Len = load_from_json_TH4(ctx, th4, TH_SIZE);
            prk4x3mLen = load_from_json_PRK4X3M(ctx, prk4x3m, SECRET_SIZE);

            infoOscoreSecretLen = load_from_json_INFO_OSCORE_SECRET(ctx, infoOscoreSecret, INFO_SIZE);
            oscoreSecretLen = load_from_json_OSCORE_SECRET(ctx, oscoreSecret, SECRET_SIZE);

            ret = test_oscore_master_secret(cipherSuite,
                                            prk4x3m,
                                            prk4x3mLen,
                                            th4,
                                            th4Len,
                                            infoOscoreSecret,
                                            infoOscoreSecretLen,
                                            oscoreSecret,
                                            oscoreSecretLen);
            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--export-salt") == 0) {

            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, &cipherSuite);

            th4Len = load_from_json_TH4(ctx, th4, TH_SIZE);
            prk4x3mLen = load_from_json_PRK4X3M(ctx, prk4x3m, SECRET_SIZE);

            infoOscoreSaltLen = load_from_json_INFO_OSCORE_SALT(ctx, infoOscoreSalt, INFO_SIZE);
            oscoreSaltLen = load_from_json_OSCORE_SALT(ctx, oscoreSalt, SECRET_SIZE);

            ret = test_oscore_master_salt(cipherSuite,
                                          prk4x3m,
                                          prk4x3mLen,
                                          th4,
                                          th4Len,
                                          infoOscoreSalt,
                                          infoOscoreSaltLen,
                                          oscoreSalt,
                                          oscoreSaltLen);

            close_edhoc_test(ctx);
        }
    }

    return ret;
}