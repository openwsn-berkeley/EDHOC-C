#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#if defined(MBEDTLS)

#include <mbedtls/sha256.h>
#include <mbedtls/dhm.h>

#elif defined(WOLFSSL)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

#endif

#include <edhoc/cipher_suites.h>

#include "util.h"
#include "json.h"
#include "crypto_internal.h"

int test_hashing(const uint8_t *msg1, size_t msg1_len, const uint8_t *data2, size_t data2_len, const uint8_t *th2) {
    int ret;
    uint8_t buf[32];

#if defined(MBEDTLS)
    mbedtls_sha256_context sha256_ctx;
#elif defined(WOLFSSL)
    wc_Sha256 sha256_ctx;
#endif

    crypt_hash_init(&sha256_ctx);

    crypt_hash_update(&sha256_ctx, msg1, msg1_len);
    crypt_hash_update(&sha256_ctx, data2, data2_len);

    crypt_hash_finish(&sha256_ctx, buf);

    assert(compare_arrays(buf, th2, 32));

    ret = EDHOC_SUCCESS;

    fail:
    return ret;
}

int test_ecdh_computation(cose_curve_t crv, const uint8_t *priv_key, size_t priv_key_len, const uint8_t *pub_key,
                          size_t pub_key_len, const uint8_t *secret, size_t secret_len) {
    ssize_t ret;
    uint8_t outbuf[COSE_MAX_KEY_LEN];

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    cose_key_t private_key;
    cose_key_t public_key;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

    cose_key_init(&public_key);
    cose_key_init(&private_key);

#if defined(MBEDTLS)

    char *pers = "edhoc_responder";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    EDHOC_CHECK_RET(mbedtls_ctr_drbg_seed(&ctr_drbg,
                                          mbedtls_entropy_func,
                                          &entropy,
                                          (const unsigned char *) pers,
                                          strlen(pers)));


    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, mbedtls_entropy_func, &entropy, NULL));
#elif defined(WOLFSSL)
    RNG rng;

    if (wc_InitRng(&rng) != EDHOC_SUCCESS)
        exit(-1);

    EDHOC_CHECK_RET(edhoc_conf_setup(&conf, EDHOC_IS_RESPONDER, NULL, &rng, NULL));
#endif

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    // manually load remote ephemeral public key
    cose_key_from_cbor(&private_key, priv_key, priv_key_len);

    // manually load remote ephemeral public key
    cose_key_from_cbor(&public_key, pub_key, pub_key_len);

    ret = crypt_compute_ecdh(
            COSE_EC_CURVE_X25519,
            &private_key,
            &public_key,
            outbuf,
            ctx.conf->f_rng,
            ctx.conf->p_rng);

    assert(compare_arrays(outbuf, secret, secret_len));

    exit:
    return ret;
}

int test_key_generation(void) {
    int ret;
    cose_key_t key;

    edhoc_ctx_t ctx;
    edhoc_conf_t conf;

    edhoc_ctx_init(&ctx);
    edhoc_conf_init(&conf);

#if defined(WOLFSSL)

#elif defined(MBEDTLS)
    char *pers = "edhoc_responder";
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
#endif

    // loading the configuration
    edhoc_ctx_setup(&ctx, &conf);

    if ((ret = crypt_gen_keypair(COSE_EC_CURVE_X25519, ctx.conf->f_rng, ctx.conf->p_rng, &key)) != EDHOC_SUCCESS) {
        goto exit;
    }

    ret = 0;
    exit:
    return ret;
}

int test_compute_prk2e(uint8_t secret[32], const uint8_t *salt, size_t salt_size, const uint8_t *result) {
    (void) salt;
    uint8_t out[32];

    assert(crypt_compute_prk2e(secret, salt, salt_size, out) == EDHOC_SUCCESS);
    assert(compare_arrays(out, result, 32));

    return EDHOC_SUCCESS;
}

int test_compute_ed25519_signature(uint8_t *sk, size_t sk_len, uint8_t *m_2, size_t m_2_len, uint8_t *expected) {
    cose_key_t authkey;
    cose_key_init(&authkey);

    uint8_t signature[64];

    cose_key_from_cbor(&authkey, sk, sk_len);

    crypt_compute_signature(COSE_EC_CURVE_ED25519, &authkey, m_2, m_2_len, NULL, NULL, signature);

    assert(compare_arrays(signature, expected, 64));

    return 0;
}

int test_edhoc_kdf(
        cose_algo_t id,
        uint8_t *prk,
        uint8_t *transcript,
        const char *label,
        uint8_t *expected,
        size_t expected_len) {

    uint8_t out[32];

    assert(crypt_edhoc_kdf(id, prk, transcript, label, out, expected_len) == EDHOC_SUCCESS);
    assert(compare_arrays(expected, out, expected_len));

    return EDHOC_SUCCESS;
}

int main(int argc, char **argv) {
    test_context_ptr ctx;
    cose_algo_t id;
    uint8_t message_1[100], data_2[100], th_2[32], prk2e[32], salt[32], prk3e2m[32], k2m[32], iv2m[16], cbor_key[100],
            m_2[250], sig[64];
    int selected, msg1_len, data2_len, th2_len, cbor_key_len, m_2_len;
    uint8_t init_ephkey[200], resp_ephkey[200], secret[50];
    int init_ephkey_len, resp_ephkey_len, secret_len, prk2e_len, salt_len, prk3e2m_len, k2m_len, iv2m_len;

    memset(message_1, 0, sizeof(message_1));
    memset(data_2, 0, sizeof(data_2));
    memset(th_2, 0, sizeof(th_2));

    if (argc == 3) {
        if (strcmp(argv[1], "--hashing") == 0) {
            ctx = load_json_test_file(argv[2]);

            msg1_len = load_from_json_MESSAGE1(ctx, message_1, sizeof(message_1));
            data2_len = load_from_json_DATA2(ctx, data_2, sizeof(data_2));
            th2_len = load_from_json_TH2(ctx, th_2, sizeof(th_2));

            assert(msg1_len != FAILURE);
            assert(data2_len != FAILURE);
            assert(th2_len != FAILURE);
            assert(th2_len == 32);

            assert(test_hashing(message_1, msg1_len, data_2, data2_len, th_2) == EDHOC_SUCCESS);

            close_test(ctx);
        } else if (strcmp(argv[1], "--ecdh") == 0) {
            ctx = load_json_test_file(argv[2]);
            assert(load_from_json_CIPHERSUITE(ctx, &selected) == 0);

            load_from_json_CIPHERSUITE(ctx, &selected);
            init_ephkey_len = load_from_json_INIT_EPHKEY(ctx, init_ephkey, sizeof(init_ephkey));
            resp_ephkey_len = load_from_json_RESP_EPHKEY(ctx, resp_ephkey, sizeof(resp_ephkey));
            secret_len = load_from_json_DH_SECRET(ctx, secret, sizeof(secret));

            assert(test_ecdh_computation(edhoc_dh_curve_from_suite(selected),
                                         init_ephkey,
                                         init_ephkey_len,
                                         resp_ephkey,
                                         resp_ephkey_len,
                                         secret,
                                         secret_len) == 0);
            close_test(ctx);
        } else if (strcmp(argv[1], "--hmac") == 0) {
            ctx = load_json_test_file(argv[2]);

            load_from_json_DH_SECRET(ctx, secret, sizeof(secret));
            load_from_json_PRK2E(ctx, prk2e, sizeof(prk2e));
            salt_len = load_from_json_RESP_SALT(ctx, salt, sizeof(salt));

            test_compute_prk2e(secret, salt, salt_len, prk2e);

            close_test(ctx);
        } else if (strcmp(argv[1], "--edhoc-kdf-k2m") == 0) {
            const char *label = "K_2m";
            ctx = load_json_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);
            load_from_json_PRK3E2M(ctx, prk3e2m, sizeof(prk3e2m));
            load_from_json_TH2(ctx, th_2, sizeof(th_2));
            k2m_len = load_from_json_K2M(ctx, k2m, sizeof(k2m));

            id = edhoc_aead_from_suite(selected);

            assert(test_edhoc_kdf(id, prk3e2m, th_2, label, k2m, k2m_len) == 0);

            close_test(ctx);
        } else if (strcmp(argv[1], "--edhoc-kdf-iv2m") == 0) {
            const char *label = "IV_2m";
            ctx = load_json_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);
            load_from_json_PRK3E2M(ctx, prk3e2m, sizeof(prk3e2m));
            load_from_json_TH2(ctx, th_2, sizeof(th_2));
            iv2m_len = load_from_json_IV2M(ctx, iv2m, sizeof(iv2m));

            id = edhoc_aead_from_suite(selected);

            assert(test_edhoc_kdf(id, prk3e2m, th_2, label, iv2m, iv2m_len) == 0);

            close_test(ctx);
        } else if (strcmp(argv[1], "--ed25519") == 0) {
            ctx = load_json_test_file(argv[2]);

            cbor_key_len = load_from_json_RESP_AUTHKEY(ctx, cbor_key, sizeof(cbor_key));
            m_2_len = load_from_json_M2(ctx, m_2, sizeof(m_2));
            load_from_json_SIGNATURE(ctx, sig, sizeof(sig));

            assert(test_compute_ed25519_signature(cbor_key, cbor_key_len, m_2, m_2_len, sig) == 0);

            return 0;

        }
    }

    return 0;
}