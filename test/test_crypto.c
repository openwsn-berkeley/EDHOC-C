#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "util.h"
#include "json.h"
#include "crypto.h"

#if defined(WOLFSSL)

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#endif /* WOLFSSL */

int test_hashing(const uint8_t *msg1, size_t msg1Len, const uint8_t *data2, size_t data2Len, const uint8_t *th2) {
    ssize_t ret;
    uint8_t buf[32];

#if defined(WOLFSSL)
    wc_Sha256 hashCtx;
#elif defined(EMPTY_X509)
    int hashCtx;
#elif defined(HACL)
    hacl_Sha256 hashCtx;
#elif defined(TINYCRYPT)
    struct tc_sha256_state_struct  hashCtx;
#else
#error "No crypto backend enabled"
#endif

    crypt_hash_init(&hashCtx);

    crypt_hash_update(&hashCtx, msg1, msg1Len);
    crypt_hash_update(&hashCtx, data2, data2Len);
    crypt_hash_finish(&hashCtx, buf);

    TEST_CHECK_EQUAL((long) memcmp(buf, th2, 32), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int test_ed25519_signature(const uint8_t *sk,
                           size_t skLen,
                           const uint8_t *msg,
                           size_t msgLen,
                           const uint8_t *signature,
                           size_t sigLen) {
    ssize_t ret;
    cose_key_t authkey;

    uint8_t result[64];
    size_t resLen;

    cose_key_init(&authkey);
    cose_key_from_cbor(&authkey, sk, skLen);

    TEST_CHECK_EQUAL((long) crypt_sign(&authkey, msg, msgLen, result, &resLen), (long) 0);
    TEST_CHECK_EQUAL(sigLen, resLen);
    TEST_CHECK_EQUAL((long) memcmp(signature, result, sigLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int test_ecdh_prk(const uint8_t *sk, size_t skLen, const uint8_t *pk, size_t pkLen, const uint8_t *prk, size_t prkLen) {
    int ret;

    uint8_t dhSecret[32];
    uint8_t zeroSalt[32] = {0};

    cose_key_t privateKey;
    cose_key_t publicKey;

    cose_key_init(&privateKey);
    cose_key_init(&publicKey);

    cose_key_from_cbor(&privateKey, sk, skLen);
    cose_key_from_cbor(&publicKey, pk, pkLen);

    TEST_CHECK_EQUAL((long) crypt_derive_prk(&privateKey, &publicKey, zeroSalt, sizeof(zeroSalt), dhSecret),
                     (long) 0);
    TEST_CHECK_EQUAL((long) memcmp(dhSecret, prk, prkLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;

}

int
test_edhoc_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, const uint8_t *expected, size_t expectedLen) {

    ssize_t ret;
    uint8_t out[256];

    TEST_CHECK_EQUAL((long) crypt_kdf(prk, info, infoLen, out, expectedLen), (long) 0);
    TEST_CHECK_EQUAL((long) memcmp(expected, out, expectedLen), (long) 0);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int main(int argc, char **argv) {

    /* buffers */
    int ret;
    test_edhoc_ctx ctx;

    uint8_t msg1[MESSAGE_1_SIZE];
    size_t msg1Len;

    uint8_t data2[DATA_2_SIZE];
    size_t data2Len;

    uint8_t m2[PAYLOAD_SIZE];
    size_t m2Len;

    uint8_t signature[SIGNATURE_SIZE];
    size_t sigLen;

    uint8_t authKey[AUTHKEY_SIZE];
    size_t authKeyLen;

    uint8_t ephKeyInit[EPHKEY_SIZE];
    size_t ephKeyInitLen;

    uint8_t ephKeyResp[EPHKEY_SIZE];
    size_t ephKeyRespLen;

    uint8_t prk[SECRET_SIZE];
    size_t prkLen;

    uint8_t info[INFO_SIZE];
    size_t infoLen;

    uint8_t th2[TH_SIZE];

    uint8_t k2m[16];

    /* test selection */

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--hashing") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            msg1Len = load_from_json_MESSAGE1(ctx, msg1, sizeof(msg1));
            data2Len = load_from_json_DATA2(ctx, data2, sizeof(data2));
            load_from_json_TH2(ctx, th2, sizeof(th2));

            ret = test_hashing(msg1, msg1Len, data2, data2Len, th2);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--ecdh-hmac") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            ephKeyInitLen = load_from_json_INIT_EPHKEY(ctx, ephKeyInit, sizeof(ephKeyInit));
            ephKeyRespLen = load_from_json_RESP_EPHKEY(ctx, ephKeyResp, sizeof(ephKeyResp));
            prkLen = load_from_json_PRK2E(ctx, prk, sizeof(prk));

            ret = test_ecdh_prk(ephKeyResp, ephKeyRespLen, ephKeyInit, ephKeyInitLen, prk, prkLen);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--kdf") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            infoLen = load_from_json_INFO_K2M(ctx, info, sizeof(info));
            load_from_json_PRK3E2M(ctx, prk, sizeof(prk));
            load_from_json_K2M(ctx, k2m, sizeof(k2m));

            ret = test_edhoc_kdf(prk, info, infoLen, k2m, sizeof(k2m));

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--edsign") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            m2Len = load_from_json_M2(ctx, m2, sizeof(m2));
            sigLen = load_from_json_SIGNATURE2(ctx, signature, sizeof(signature));
            authKeyLen = load_from_json_RESP_AUTHKEY(ctx, authKey, sizeof(authKey));

            ret = test_ed25519_signature(authKey, authKeyLen, m2, m2Len, signature, sigLen);

            close_edhoc_test(ctx);
        }
    }

    return ret;
}
