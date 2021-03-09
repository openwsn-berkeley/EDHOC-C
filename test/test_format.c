#include <assert.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <cipher_suites.h>

#include "util.h"
#include "json.h"

#include "format.h"

int test_message1_encode(corr_t corr,
                         method_t m,
                         cipher_suite_id_t id,
                         cose_key_t *k,
                         const uint8_t *cidi,
                         size_t cidi_len,
                         ad_cb_t ad1,
                         uint8_t *expected,
                         size_t expected_len) {
    ssize_t ret;
    uint8_t buffer[MESSAGE_1_SIZE];

    CHECK_TEST_RET_EQ(edhoc_msg1_encode(corr, m, id, k, cidi, cidi_len, ad1, buffer, MESSAGE_1_SIZE),
                      (long) expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(expected, buffer, expected_len), (long) 0);

    exit:
    return ret;
}

int test_message1_decode(const uint8_t *msg_buf,
                         size_t msg_buf_len,
                         uint8_t method_corr,
                         const uint8_t *g_x,
                         size_t g_x_len,
                         const uint8_t *conn_idi,
                         size_t conn_idi_len) {

    ssize_t ret;
    edhoc_msg1_t msg1;
    uint8_t temp[MESSAGE_1_SIZE];

    memset(&msg1, 0, sizeof(edhoc_msg1_t));

    CHECK_TEST_RET_EQ(edhoc_msg1_decode(&msg1, msg_buf, msg_buf_len), (long) 0);
    CHECK_TEST_RET_EQ(msg1.method_corr, (long) method_corr);

    CHECK_TEST_RET_EQ(msg1.cidi_len, (long) conn_idi_len);
    memcpy(temp, msg1.cidi, msg1.cidi_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, conn_idi, conn_idi_len), (long) 0);

    CHECK_TEST_RET_EQ(msg1.g_x_len, (long) g_x_len);
    memcpy(temp, msg1.g_x, msg1.g_x_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, g_x, g_x_len), (long) 0);

    exit:
    return ret;
}

int test_message2_encode(const uint8_t *data2,
                         size_t data2_len,
                         const uint8_t *ct2,
                         size_t ct2_len,
                         uint8_t *expected,
                         size_t expected_len) {
    ssize_t ret;
    uint8_t buffer[MESSAGE_2_SIZE];

    CHECK_TEST_RET_EQ(edhoc_msg2_encode(data2, data2_len, ct2, ct2_len, buffer, MESSAGE_2_SIZE), (long) expected_len);
    CHECK_TEST_RET_EQ(compare_arrays(expected, buffer, expected_len), (long) 0);

    exit:
    return ret;


}

int test_message2_decode(corr_t correlation,
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
    edhoc_msg2_t msg2;
    uint8_t temp[MESSAGE_2_SIZE];

    memset(&msg2, 0, sizeof(edhoc_msg2_t));

    CHECK_TEST_RET_EQ(edhoc_msg2_decode(&msg2, correlation, msg_buf, msg_buf_len), (long) 0);

    CHECK_TEST_RET_EQ(msg2.cidi_len, (long) conn_idi_len);

    // passing NULL to memcpy is undefined behavior
    memcpy(temp, msg2.cidi, msg2.cidi_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, conn_idi, conn_idi_len), (long) 0);

    CHECK_TEST_RET_EQ(msg2.g_y_len, (long) g_y_len);
    memcpy(temp, msg2.g_y, msg2.g_y_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, g_y, g_y_len), (long) 0);

    CHECK_TEST_RET_EQ(msg2.cidr_len, (long) conn_idr_len);

    memcpy(temp, msg2.cidr, msg2.cidr_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, conn_idr, conn_idr_len), (long) 0);

    CHECK_TEST_RET_EQ(msg2.ciphertext_len, (long) ciphertext_2_len);
    memcpy(temp, msg2.ciphertext, msg2.ciphertext_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, ciphertext_2, msg2.ciphertext_len), (long) 0);

    exit:
    return ret;
}

int test_message3_decode(corr_t correlation,
                         const uint8_t *msg_buf,
                         size_t msg_buf_len,
                         const uint8_t *conn_idr,
                         size_t conn_idr_len,
                         uint8_t *ciphertext_3,
                         size_t ciphertext_3_len) {

    ssize_t ret;
    edhoc_msg3_t msg3;
    uint8_t temp[MESSAGE_3_SIZE];

    memset(&msg3, 0, sizeof(edhoc_msg3_t));

    CHECK_TEST_RET_EQ(edhoc_msg3_decode(&msg3, correlation, msg_buf, msg_buf_len), (long) 0);

    CHECK_TEST_RET_EQ(msg3.cidr_len, (long) conn_idr_len);
    memcpy(temp, msg3.cidr, msg3.cidr_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, conn_idr, conn_idr_len), (long) 0);

    CHECK_TEST_RET_EQ(msg3.ciphertext_len, (long) ciphertext_3_len);
    memcpy(temp, msg3.ciphertext, msg3.ciphertext_len);
    CHECK_TEST_RET_EQ(compare_arrays(temp, ciphertext_3, msg3.ciphertext_len), (long) 0);


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
    test_edhoc_ctx ctx;

    int corr, selected, key_length, iv_length, method, method_corr;
    cose_algo_t id;

    uint8_t m1[MESSAGE_1_SIZE];
    size_t msg1_len;
    uint8_t m2[MESSAGE_2_SIZE];
    size_t msg2_len;
    uint8_t m3[MESSAGE_3_SIZE];
    size_t msg3_len;

    uint8_t g_x[RAW_PUBLIC_KEY];
    size_t g_x_len;
    uint8_t g_y[RAW_PUBLIC_KEY];
    size_t g_y_len;

    uint8_t cidi[CONN_ID_SIZE];
    size_t cidi_len;
    uint8_t cidr[CONN_ID_SIZE];
    size_t cidr_len;

    uint8_t ephkey[EPHKEY_SIZE];
    size_t ephkey_len;
    uint8_t data2[DATA_2_SIZE];
    size_t data2_len;
    uint8_t th2[TH_SIZE];
    size_t th2_len;
    uint8_t info_k2m[INFO_SIZE];
    size_t info_k2m_len;
    uint8_t info_iv2m[INFO_SIZE];
    size_t info_iv2m_len;
    uint8_t ciphertext_2[PAYLOAD_SIZE];
    size_t ct2_len;
    uint8_t ciphertext_3[PAYLOAD_SIZE];
    size_t ct3_len;

    /* test selection */

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--encode-msg1") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);
            load_from_json_CIPHERSUITE(ctx, &selected);

            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            ephkey_len = load_from_json_INIT_EPHKEY(ctx, ephkey, sizeof(ephkey));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, cidi_len);
            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));

            cose_key_t init_ephkey;
            cose_key_init(&init_ephkey);
            cose_key_from_cbor(&init_ephkey, ephkey, ephkey_len);

            ret = test_message1_encode(corr, method, selected, &init_ephkey, cidi, cidi_len, NULL, m1, msg1_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--decode-msg1") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_METHOD(ctx, &method);
            load_from_json_CORR(ctx, &corr);

            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            g_x_len = load_from_json_G_X(ctx, g_x, sizeof(g_x));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));

            assert(msg1_len > 0);
            assert(g_x_len > 0);
            assert(cidi_len >= 0);

            method_corr = (4 * method) + corr;

            ret = test_message1_decode(m1, msg1_len, method_corr, g_x, g_x_len, cidi, cidi_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--decode-msg3") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, &corr);

            msg3_len = load_from_json_MESSAGE3(ctx, m3, sizeof(m3));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ct3_len = load_from_json_CIPHERTEXT3(ctx, ciphertext_3, sizeof(ciphertext_3));

            ret = test_message3_decode(corr, m3, msg3_len, cidr, cidr_len, ciphertext_3, ct3_len);

            close_edhoc_test(ctx);

        } else if (strcmp(argv[1], "--encode-msg2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            data2_len = load_from_json_DATA2(ctx, data2, DATA_2_SIZE);
            ct2_len = load_from_json_CIPHERTEXT2(ctx, ciphertext_2, PAYLOAD_SIZE);
            msg2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));

            ret = test_message2_encode(data2, data2_len, ciphertext_2, ct2_len, m2, msg2_len);

            close_edhoc_test(ctx);

        } else if (strcmp(argv[1], "--decode-msg2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, (int *) &corr);

            msg2_len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            g_y_len = load_from_json_G_Y(ctx, g_y, sizeof(g_y));
            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ct2_len = load_from_json_CIPHERTEXT2(ctx, ciphertext_2, sizeof(ciphertext_2));

            assert(msg2_len > 0);
            assert(g_y_len > 0);
            assert(cidi_len >= 0);
            assert(cidr_len >= 0);
            assert(ct2_len > 0);

            ret = test_message2_decode(corr,
                                       m2,
                                       msg2_len,
                                       g_y,
                                       g_y_len,
                                       cidi,
                                       cidi_len,
                                       cidr,
                                       cidr_len,
                                       ciphertext_2,
                                       ct2_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--encode-data2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, (int *) &corr);

            cidi_len = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidr_len = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ephkey_len = load_from_json_RESP_EPHKEY(ctx, ephkey, sizeof(ephkey));
            data2_len = load_from_json_DATA2(ctx, data2, sizeof(data2));

            assert(data2_len > 0);
            assert(ephkey_len > 0);
            assert(cidi_len >= 0);
            assert(cidr_len >= 0);

            cose_key_t resp_ephkey;
            cose_key_init(&resp_ephkey);
            cose_key_from_cbor(&resp_ephkey, ephkey, ephkey_len);

            ret = test_data2_encode(corr, cidi, cidi_len, cidr, cidr_len, resp_ephkey, data2, data2_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-k2m") == 0) {
            const char *label = "K_2m";
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);

            info_k2m_len = load_from_json_INFO_K2M(ctx, info_k2m, sizeof(info_k2m));
            th2_len = load_from_json_TH2(ctx, th2, sizeof(th2));

            assert(info_k2m_len > 0);
            assert(th2_len > 0);

            id = edhoc_cipher_suite_from_id(selected)->aead_algo;
            key_length = cose_aead_info_from_id(id)->key_length;

            ret = test_info_encode(id, th2, label, key_length, info_k2m, info_k2m_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--encode-info-iv2m") == 0) {
            const char *label = "IV_2m";
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CIPHERSUITE(ctx, (int *) &selected);

            info_iv2m_len = load_from_json_INFO_IV2M(ctx, info_iv2m, sizeof(info_iv2m));
            th2_len = load_from_json_TH2(ctx, th2, sizeof(th2));

            assert(info_iv2m_len > 0);
            assert(th2_len > 0);

            id = edhoc_cipher_suite_from_id(selected)->aead_algo;
            iv_length = cose_aead_info_from_id(id)->iv_length;

            ret = test_info_encode(id, th2, label, iv_length, info_iv2m, info_iv2m_len);

            close_edhoc_test(ctx);

        }
    }


    return ret;
}
