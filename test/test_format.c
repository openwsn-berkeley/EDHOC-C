#include <string.h>

#include "format.h"
#include "ciphersuites.h"

#include "json.h"
#include "util.h"

int test_msg1_encode(const edhoc_msg1_t *msg1, const uint8_t *expected, size_t expected_len) {
    int ret;
    ssize_t message1_len;
    uint8_t message1[MESSAGE_1_SIZE];

    ret = TEST_FAILED;

    message1_len = format_msg1_encode(msg1, message1, MESSAGE_1_SIZE);

    TEST_CHECK_EQUAL(expected_len, message1_len);

    TEST_CHECK_EQUAL((long) compare_arrays(message1, expected, expected_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_msg1_decode(const uint8_t *m1,
                     size_t m1_len,
                     uint8_t method_corr,
                     const uint8_t *g_x,
                     size_t g_x_len,
                     const uint8_t *cidi,
                     size_t cidi_len) {
    int ret;
    edhoc_msg1_t msg1;

    ret = TEST_FAILED;

    format_msg1_init(&msg1);

    TEST_CHECK_EQUAL((long) format_msg1_decode(&msg1, m1, m1_len), (long) 0);
    TEST_CHECK_EQUAL((long) msg1.methodCorr, (long) method_corr);
    TEST_CHECK_EQUAL(msg1.gX.xLen, g_x_len);
    TEST_CHECK_EQUAL((long) compare_arrays(msg1.gX.x, g_x, g_x_len), (long) 0);

    TEST_CHECK_EQUAL(msg1.cidi.length, cidi_len);
    if (msg1.cidi.length == 1)
        TEST_CHECK_EQUAL(compare_arrays((const uint8_t *) &msg1.cidi.integer, cidi, cidi_len), (long) 0);
    else
        TEST_CHECK_EQUAL(compare_arrays(msg1.cidi.bstr, cidi, cidi_len), (long) 0);


    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_msg2_encode(const edhoc_msg2_t *msg2, corr_t corr, const uint8_t *expected, size_t expected_len) {
    int ret;
    ssize_t message2_len;
    uint8_t message2[MESSAGE_2_SIZE];

    ret = TEST_FAILED;

    message2_len = format_msg2_encode(msg2, corr, message2, MESSAGE_1_SIZE);

    TEST_CHECK_EQUAL(expected_len, message2_len);

    TEST_CHECK_EQUAL(compare_arrays(message2, expected, expected_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}


int test_msg2_decode(const uint8_t *m2,
                     size_t m2_len,
                     corr_t corr,
                     const cipher_suite_t *suite,
                     const uint8_t *cidi,
                     size_t cidi_len,
                     const uint8_t *gY,
                     size_t gYLen,
                     const uint8_t *cidr,
                     size_t cidr_len,
                     const uint8_t *ct2,
                     size_t ct2_len) {
    int ret;
    edhoc_msg2_t msg2;

    ret = TEST_FAILED;

    format_msg2_init(&msg2);

    TEST_CHECK_EQUAL((long) format_msg2_decode(&msg2, corr, suite, m2, m2_len), (long) 0);

    // only when the correlation value is CORR_2_3 or NO_CORR there will be a cidi included in this message.
    if (corr == CORR_2_3 || corr == NO_CORR) {
        TEST_CHECK_EQUAL(msg2.data2.cidi.length, cidi_len);
        if (msg2.data2.cidi.length == 1)
            TEST_CHECK_EQUAL(compare_arrays((const uint8_t *) &msg2.data2.cidi.integer, cidi, cidi_len), (long) 0);
        else
            TEST_CHECK_EQUAL(compare_arrays(msg2.data2.cidi.bstr, cidi, cidi_len), (long) 0);
    } else {
        TEST_CHECK_EQUAL(msg2.data2.cidi.length, (long) 0);
    }

    TEST_CHECK_EQUAL(msg2.data2.gY.xLen, gYLen);
    TEST_CHECK_EQUAL((long) compare_arrays(msg2.data2.gY.x, gY, gYLen), (long) 0);

    TEST_CHECK_EQUAL(msg2.data2.cidr.length, cidr_len);
    if (msg2.data2.cidr.length == 1)
        TEST_CHECK_EQUAL(compare_arrays((const uint8_t *) &msg2.data2.cidr.integer, cidr, cidr_len), (long) 0);
    else
        TEST_CHECK_EQUAL(compare_arrays(msg2.data2.cidr.bstr, cidr, cidr_len), (long) 0);

    TEST_CHECK_EQUAL(msg2.ciphertext2Len, ct2_len);
    TEST_CHECK_EQUAL((long) compare_arrays(msg2.ciphertext2, ct2, ct2_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_msg3_encode(const edhoc_msg3_t *msg3, corr_t corr, const uint8_t *expected, size_t expected_len) {
    int ret;
    ssize_t message3_len;
    uint8_t message3[MESSAGE_3_SIZE];

    ret = TEST_FAILED;

    message3_len = format_msg3_encode(msg3, corr, message3, MESSAGE_1_SIZE);

    TEST_CHECK_EQUAL(expected_len, message3_len);

    TEST_CHECK_EQUAL(compare_arrays(message3, expected, expected_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_msg3_decode(const uint8_t *m3,
                     size_t m3_len,
                     corr_t corr,
                     const uint8_t *cidr,
                     size_t cidr_len,
                     const uint8_t *ct3,
                     size_t ct3_len) {
    int ret;
    edhoc_msg3_t msg3;

    ret = TEST_FAILED;

    format_msg3_init(&msg3);

    TEST_CHECK_EQUAL((long) format_msg3_decode(&msg3, corr, m3, m3_len), (long) 0);

    // only when the correlation value is CORR_1_2 or NO_CORR there will be a cidr included in this message.
    if (corr == CORR_1_2 || corr == NO_CORR) {
        TEST_CHECK_EQUAL(msg3.data3.cidr.length, cidr_len);
        if (msg3.data3.cidr.length == 1)
            TEST_CHECK_EQUAL(compare_arrays((const uint8_t *) &msg3.data3.cidr.integer, cidr, cidr_len), (long) 0);
        else
            TEST_CHECK_EQUAL(compare_arrays(msg3.data3.cidr.bstr, cidr, cidr_len), (long) 0);
    } else {
        TEST_CHECK_EQUAL(msg3.data3.cidr.length, (long) 0);
    }

    TEST_CHECK_EQUAL(msg3.ciphertext3Len, ct3_len);
    TEST_CHECK_EQUAL((long) compare_arrays(msg3.ciphertext3, ct3, ct3_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}


int main(int argc, char **argv) {

    /* temporary buffers */
    ssize_t ret;
    test_edhoc_ctx ctx;

    int corr, selected, method;
    cose_algo_id_t id;
    const cipher_suite_t *s;

    uint8_t m1[MESSAGE_1_SIZE];
    size_t msg1_len;
    uint8_t m2[MESSAGE_2_SIZE];
    size_t msg2Len;
    uint8_t m3[MESSAGE_3_SIZE];
    size_t msg3_len;

    uint8_t gX[RAW_PUBLIC_KEY];
    size_t gXLen;
    uint8_t gY[RAW_PUBLIC_KEY];
    size_t gYLen;

    uint8_t cidi[CONN_ID_SIZE];
    size_t cidiLen;
    uint8_t cidr[CONN_ID_SIZE];
    size_t cidrLen;

    uint8_t ephKey[EPHKEY_SIZE];
    size_t ephKeyLen;
    uint8_t ct2[PAYLOAD_SIZE];
    size_t ct2Len;
    uint8_t ct3[PAYLOAD_SIZE];
    size_t ct3Len;

    /* test selection */

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--encode-msg1") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            edhoc_msg1_t msg1;
            format_msg1_init(&msg1);

            load_from_json_CORR(ctx, &corr);
            load_from_json_METHOD(ctx, &method);
            msg1.methodCorr = method * 4 + corr;

            load_from_json_CIPHERSUITE(ctx, &selected);
            msg1.cipherSuite = edhoc_cipher_suite_from_id(selected);

            msg1.cidi.length = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            if (msg1.cidi.length > 1) {
                msg1.cidi.bstr = cidi;
            } else {
                msg1.cidi.integer = *cidi;
            }

            ephKeyLen = load_from_json_INIT_EPHKEY(ctx, ephKey, sizeof(ephKey));
            cose_key_from_cbor(&msg1.gX, ephKey, ephKeyLen);

            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));

            ret = test_msg1_encode(&msg1, m1, msg1_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--decode-msg1") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_METHOD(ctx, &method);
            load_from_json_CORR(ctx, &corr);

            msg1_len = load_from_json_MESSAGE1(ctx, m1, sizeof(m1));
            gXLen = load_from_json_G_X(ctx, gX, sizeof(gX));
            cidiLen = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));

            ret = test_msg1_decode(m1, msg1_len, 4 * method + corr, gX, gXLen, cidi, cidiLen);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--encode-msg2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            edhoc_msg2_t msg2;
            format_msg2_init(&msg2);

            load_from_json_CORR(ctx, &corr);

            msg2.data2.cidi.length = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            if (msg2.data2.cidi.length > 1) {
                msg2.data2.cidi.bstr = cidi;
            } else {
                msg2.data2.cidi.integer = *cidi;
            }

            ephKeyLen = load_from_json_RESP_EPHKEY(ctx, ephKey, sizeof(ephKey));
            cose_key_from_cbor(&msg2.data2.gY, ephKey, ephKeyLen);

            msg2.data2.cidr.length = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            if (msg2.data2.cidr.length > 1) {
                msg2.data2.cidr.bstr = cidr;
            } else {
                msg2.data2.cidr.integer = *cidr;
            }

            msg2.ciphertext2Len = load_from_json_CIPHERTEXT2(ctx, ct2, PAYLOAD_SIZE);
            msg2.ciphertext2 = ct2;

            msg2Len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));

            ret = test_msg2_encode(&msg2, corr, m2, msg2Len);

            close_edhoc_test(ctx);

        } else if (strcmp(argv[1], "--decode-msg2") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, (int *) &corr);
            load_from_json_CIPHERSUITE(ctx, &selected);
            s = edhoc_cipher_suite_from_id(selected);

            msg2Len = load_from_json_MESSAGE2(ctx, m2, sizeof(m2));
            gYLen = load_from_json_G_Y(ctx, gY, sizeof(gY));
            cidiLen = load_from_json_CONN_IDI(ctx, cidi, sizeof(cidi));
            cidrLen = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ct2Len = load_from_json_CIPHERTEXT2(ctx, ct2, sizeof(ct2));

            ret = test_msg2_decode(m2, msg2Len, corr, s, cidi, cidiLen, gY, gYLen, cidr, cidrLen, ct2, ct2Len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--encode-msg3") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            edhoc_msg3_t msg3;
            format_msg3_init(&msg3);

            load_from_json_CORR(ctx, &corr);

            msg3.data3.cidr.length = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            if (msg3.data3.cidr.length > 1) {
                msg3.data3.cidr.bstr = cidr;
            } else {
                msg3.data3.cidr.integer = *cidr;
            }

            msg3.ciphertext3Len = load_from_json_CIPHERTEXT3(ctx, ct3, PAYLOAD_SIZE);
            msg3.ciphertext3 = ct3;

            msg3_len = load_from_json_MESSAGE3(ctx, m3, sizeof(m3));

            ret = test_msg3_encode(&msg3, corr, m3, msg3_len);

            close_edhoc_test(ctx);
        } else if (strcmp(argv[1], "--decode-msg3") == 0) {
            ctx = load_json_edhoc_test_file(argv[2]);

            load_from_json_CORR(ctx, &corr);

            msg3_len = load_from_json_MESSAGE3(ctx, m3, sizeof(m3));
            cidrLen = load_from_json_CONN_IDR(ctx, cidr, sizeof(cidr));
            ct3Len = load_from_json_CIPHERTEXT3(ctx, ct3, sizeof(ct3));

            ret = test_msg3_decode(m3, msg3_len, corr, cidr, cidrLen, ct3, ct3Len);

            close_edhoc_test(ctx);
        }
    }


    return ret;
}
