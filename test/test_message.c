#include <assert.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <edhoc/cipher_suites.h>

#include "util.h"
#include "json.h"

#include "edhoc_internal.h"

int test_message1_decode(const uint8_t *msg_buf,
                         size_t msg_buf_len,
                         uint8_t method_corr,
                         const uint8_t *g_x,
                         size_t g_x_len,
                         const uint8_t *conn_idi,
                         size_t conn_idi_len) {

    edhoc_ctx_t ctx;
    edhoc_ctx_init(&ctx);

    assert(edhoc_msg1_decode(&ctx, msg_buf, msg_buf_len) == 0);
    assert(ctx.correlation == method_corr % 4);
    assert(*ctx.method == (method_corr - ctx.correlation) / 4);
    assert(ctx.session.cidi_len == conn_idi_len);
    assert(compare_arrays(ctx.session.cidi, conn_idi, conn_idi_len));
    assert(ctx.remote_eph_key.x_len == g_x_len);
    assert(compare_arrays(ctx.remote_eph_key.x, g_x, g_x_len));

    return 0;
}

int test_data2_encode(corr_t corr,
                      uint8_t *cidi,
                      size_t cidi_len,
                      uint8_t *cidr,
                      size_t cidr_len,
                      cose_key_t eph_key,
                      uint8_t *expected,
                      size_t expected_len) {
    uint8_t mbuf[COSE_MAX_KEY_LEN + 2 * EDHOC_MAX_CID_LEN];
    ssize_t ret;

    ret = edhoc_data2_encode(corr, cidi, cidi_len, cidr, cidr_len, &eph_key, mbuf, sizeof(mbuf));
    assert(expected_len == ret);
    assert(compare_arrays(expected, mbuf, expected_len));

    return 0;
}

int test_info_encode(cose_algo_t id,
                     const uint8_t *th,
                     const char *label,
                     size_t len,
                     uint8_t *expected,
                     size_t expected_len) {

    uint8_t mbuf[100];
    ssize_t ret;

    memset(mbuf, 0, sizeof(mbuf));
    ret = edhoc_info_encode(id, th, label, len, mbuf, sizeof(mbuf));
    assert(expected_len == ret);
    assert(compare_arrays(expected, mbuf, expected_len));

    return 0;
}


int main(int argc, char **argv) {
    test_context_ptr ctx;
    corr_t corr;
    cipher_suite_t selected;
    int key_length, iv_length;
    cose_algo_t id;
    uint8_t message_1[100], g_x[50], cidi[4], cidr[4], eph_key_buf[100], data2[
            COSE_MAX_KEY_LEN + 2 * EDHOC_MAX_CID_LEN], th_2[COSE_DIGEST_LEN], info_k2m[50], info_iv2m[50];
    size_t msg1_len, g_x_len, cidi_len, cidr_len, eph_key_len, data2_len, info_k2m_len, info_iv2m_len;
    cose_key_t ephkey;

    cose_key_init(&ephkey);

    if (argc == 3) {
        if (strcmp(argv[1], "--decode-msg1") == 0) {
            ctx = load_json_test_file(argv[2]);
            msg1_len = load_from_json_MESSAGE1(ctx, message_1, sizeof(message_1));
            g_x_len = load_from_json_G_X(ctx, g_x, sizeof(g_x));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));

            assert(test_message1_decode(message_1, msg1_len, 1, g_x, g_x_len, cidi, cidi_len) == 0);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-data2") == 0) {
            ctx = load_json_test_file(argv[2]);

            load_from_json_CORR(ctx, (int *) &corr);
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            eph_key_len = load_from_json_RESP_EPHKEY(ctx, eph_key_buf, sizeof(eph_key_buf));
            data2_len = load_from_json_DATA2(ctx, data2, sizeof(data2));

            cose_key_from_cbor(&ephkey, eph_key_buf, eph_key_len);

            test_data2_encode(corr, cidi, cidi_len, cidr, cidr_len, ephkey, data2, data2_len);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-k2m") == 0) {
            const char *label = "K_2m";
            ctx = load_json_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);
            info_k2m_len = load_from_json_INFO_K2M(ctx, info_k2m, sizeof(info_k2m));

            id = edhoc_aead_from_suite(selected);
            key_length = cose_key_len_from_alg(id);

            load_from_json_TH2(ctx, th_2, sizeof(th_2));

            assert(test_info_encode(id, th_2, label, key_length, info_k2m, info_k2m_len) == 0);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-iv2m") == 0) {
            const char *label = "IV_2m";
            ctx = load_json_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);
            info_iv2m_len = load_from_json_INFO_IV2M(ctx, info_iv2m, sizeof(info_k2m));

            id = edhoc_aead_from_suite(selected);
            iv_length = cose_iv_len_from_alg(id);

            load_from_json_TH2(ctx, th_2, sizeof(th_2));

            assert(test_info_encode(id, th_2, label, iv_length, info_iv2m, info_iv2m_len) == 0);

            close_test(ctx);

        }
    }


    return 0;
}
