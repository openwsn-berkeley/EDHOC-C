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

    ssize_t ret;

    edhoc_ctx_t ctx;
    edhoc_ctx_init(&ctx);

    CHECK_TEST_RET_EQ(edhoc_msg1_decode(&ctx, msg_buf, msg_buf_len), (long) 0);
    CHECK_TEST_RET_EQ(ctx.correlation, (long) method_corr % 4);
    CHECK_TEST_RET_EQ(*ctx.method, (long) (method_corr - ctx.correlation) / 4);
    CHECK_TEST_RET_EQ(ctx.session.cidi_len, (long) conn_idi_len);
    CHECK_TEST_RET_EQ(compare_arrays(ctx.session.cidi, conn_idi, conn_idi_len), (long) 0);
    CHECK_TEST_RET_EQ(ctx.remote_eph_key.x_len, (long) g_x_len);
    CHECK_TEST_RET_EQ(compare_arrays(ctx.remote_eph_key.x, g_x, g_x_len), (long) 0);

    exit:
    return ret;
}

int test_message2_decode(edhoc_ctx_t *ctx,
                         const uint8_t *msg_buf,
                         size_t msg_buf_len,
                         const uint8_t *g_y,
                         size_t g_y_len,
                         const uint8_t *conn_idi,
                         size_t conn_idi_len,
                         const uint8_t *conn_idr,
                         size_t conn_idr_len,
                         uint8_t *ciphertext_2,
                         size_t ciphertext_2_len) {
    ssize_t ret;

    CHECK_TEST_RET_EQ(edhoc_msg2_decode(ctx, msg_buf, msg_buf_len), (long) 0);
    CHECK_TEST_RET_EQ(ctx->session.cidi_len, (long) conn_idi_len);
    CHECK_TEST_RET_EQ(ctx->remote_eph_key.x_len, (long) g_y_len);
    CHECK_TEST_RET_EQ(compare_arrays(ctx->remote_eph_key.x, g_y, g_y_len), (long) 0);
    CHECK_TEST_RET_EQ(compare_arrays(ctx->session.cidi, conn_idi, conn_idi_len), (long) 0);
    CHECK_TEST_RET_EQ(ctx->session.cidr_len, (long) conn_idr_len);
    CHECK_TEST_RET_EQ(compare_arrays(ctx->session.cidr, conn_idr, conn_idr_len), (long) 0);
    CHECK_TEST_RET_EQ(ctx->ct_or_pld_2_len, (long) ciphertext_2_len);
    CHECK_TEST_RET_EQ(compare_arrays(ctx->ct_or_pld_2, ciphertext_2, ctx->ct_or_pld_2_len), (long) 0);

    exit:
    return ret;
}

int test_data2_encode(corr_t corr,
                      uint8_t *cidi,
                      size_t cidi_len,
                      uint8_t *cidr,
                      size_t cidr_len,
                      cose_key_t eph_key,
                      uint8_t *expected,
                      size_t expected_len) {
    ssize_t ret;
    uint8_t mbuf[expected_len];

    CHECK_TEST_RET_EQ(edhoc_data2_encode(corr, cidi, cidi_len, cidr, cidr_len, &eph_key, mbuf, sizeof(mbuf)),
                      (long) expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(expected, mbuf, expected_len), (long) 0);

    exit:
    return ret;
}

int test_info_encode(cose_algo_t id,
                     const uint8_t *th,
                     const char *label,
                     size_t len,
                     uint8_t *expected,
                     size_t expected_len) {

    uint8_t mbuf[expected_len];
    ssize_t ret;

    CHECK_TEST_RET_EQ(edhoc_info_encode(id, th, label, len, mbuf, sizeof(mbuf)), expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(expected, mbuf, expected_len), (long) 0);

    exit:
    return ret;
}


int main(int argc, char **argv) {

    /* temporary buffers */
    ssize_t ret;
    test_context_ptr ctx;

    int corr, selected, key_length, iv_length;
    cose_algo_t id;

    uint8_t m1[MESSAGE_1_SIZE];
    uint8_t g_x[RAW_PUBLIC_KEY];
    uint8_t cidi[CONN_ID_SIZE];
    uint8_t cidr[CONN_ID_SIZE];
    uint8_t ephkey[EPHKEY_SIZE];
    uint8_t data2[EHDOC_DATA_2_SIZE];
    uint8_t th_2[EDHOC_TH_SIZE];
    uint8_t info_k2m[EDHOC_INFO_SIZE];
    uint8_t info_iv2m[EDHOC_INFO_SIZE];
    uint8_t m2[MESSAGE_2_SIZE];
    uint8_t g_y[RAW_PUBLIC_KEY];
    uint8_t ciphertext_2[EDHOC_PAYLOAD_SIZE];

    size_t msg1_len, g_x_len, cidi_len, cidr_len, eph_key_len, data2_len, info_k2m_len, info_iv2m_len, msg2_len,
            g_y_len, ciphertext2_len, th2_len;

    /* test selection */

    ret = 0;

    if (argc == 3) {
        if (strcmp(argv[1], "--decode-msg1") == 0) {
            ctx = load_json_test_file(argv[2]);

            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            g_x_len = load_from_json_G_X(ctx, g_x, sizeof(g_x));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));

            assert(msg1_len > 0);
            assert(g_x_len > 0);
            assert(cidi_len >= 0);

            ret = test_message1_decode(m1, msg1_len, 1, g_x, g_x_len, cidi, cidi_len);

            close_test(ctx);
        } else if (strcmp(argv[1], "--decode-msg2") == 0) {
            ctx = load_json_test_file(argv[2]);

            assert(load_from_json_CIPHERSUITE(ctx, (int *) &selected) == 0);

            msg2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            g_y_len = load_from_json_G_Y(ctx, g_y, sizeof(g_y));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ciphertext2_len = load_from_json_CIPHERTEXT2(ctx, ciphertext_2, sizeof(ciphertext_2));

            assert(msg2_len > 0);
            assert(g_y_len > 0);
            assert(cidi_len >= 0);
            assert(cidr_len >= 0);
            assert(ciphertext2_len > 0);

            edhoc_ctx_t edhoc_ctx;
            edhoc_ctx_init(&edhoc_ctx);
            edhoc_ctx.session.selected_suite = (cipher_suite_t *) edhoc_select_suite(selected);

            ret = test_message2_decode(&edhoc_ctx,
                                        m2,
                                        msg2_len,
                                        g_y,
                                        g_y_len,
                                        cidi,
                                        cidi_len,
                                        cidr,
                                        cidr_len,
                                        ciphertext_2,
                                        ciphertext2_len);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-data2") == 0) {
            ctx = load_json_test_file(argv[2]);

            assert(load_from_json_CORR(ctx, (int *) &corr) == 0);

            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            eph_key_len = load_from_json_RESP_EPHKEY(ctx, ephkey, sizeof(ephkey));
            data2_len = load_from_json_DATA2(ctx, data2, sizeof(data2));

            assert(data2_len > 0);
            assert(eph_key_len > 0);
            assert(cidi_len >= 0);
            assert(cidr_len >= 0);

            cose_key_t resp_ephkey;
            cose_key_init(&resp_ephkey);
            cose_key_from_cbor(&resp_ephkey, ephkey, eph_key_len);

            ret = test_data2_encode(corr, cidi, cidi_len, cidr, cidr_len, resp_ephkey, data2, data2_len);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-k2m") == 0) {
            const char *label = "K_2m";
            ctx = load_json_test_file(argv[2]);

            assert(load_from_json_CIPHERSUITE(ctx, (int *) &selected) == 0);

            info_k2m_len = load_from_json_INFO_K2M(ctx, info_k2m, sizeof(info_k2m));
            th2_len = load_from_json_TH2(ctx, th_2, sizeof(th_2));

            assert(info_k2m_len > 0);
            assert(th2_len > 0);

            id = edhoc_aead_from_suite(selected);
            key_length = cose_key_len_from_alg(id);

            ret = test_info_encode(id, th_2, label, key_length, info_k2m, info_k2m_len);

            close_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-iv2m") == 0) {
            const char *label = "IV_2m";
            ctx = load_json_test_file(argv[2]);

            assert(load_from_json_CIPHERSUITE(ctx, (int *) &selected) == 0);

            info_iv2m_len = load_from_json_INFO_IV2M(ctx, info_iv2m, sizeof(info_iv2m));
            th2_len = load_from_json_TH2(ctx, th_2, sizeof(th_2));

            assert(info_iv2m_len > 0);
            assert(th2_len > 0);

            id = edhoc_aead_from_suite(selected);
            iv_length = cose_iv_len_from_alg(id);

            ret = test_info_encode(id, th_2, label, iv_length, info_iv2m, info_iv2m_len);

            close_test(ctx);

        }
    }


    return ret;
}
