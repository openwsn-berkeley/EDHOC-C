#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cbor.h"
#include "json.h"
#include "util.h"

#define CBOR_BUFFER     (100)

int test_cbor_bytes_decoding(const uint8_t *in, size_t ilen, const uint8_t *out, size_t olen) {
    ssize_t ret;

    size_t written;
    const uint8_t *tmp;
    size_t len;

    tmp = NULL;
    len = 0;

    written = cbor_bytes_decode(&tmp, &len, in, 0, ilen);
    CHECK_TEST_RET_EQ(written, ilen);
    CHECK_TEST_RET_EQ(len, olen);
    CHECK_TEST_RET_EQ(compare_arrays(tmp, out, olen), (long) 0);

    ret = 0;
    exit:
    return ret;
}

int test_cbor_bytes_encoding(const uint8_t *in, size_t ilen, const uint8_t *out, size_t olen) {
    ssize_t ret;

    size_t written;
    uint8_t tmp_buffer[CBOR_BUFFER];

    written = cbor_bytes_encode(in, ilen, tmp_buffer, 0, CBOR_BUFFER);
    CHECK_TEST_RET_EQ(written, olen);
    CHECK_TEST_RET_EQ(compare_arrays(tmp_buffer, out, olen), (long) 0);

    ret = 0;
    exit:
    return ret;
}

int test_cbor_suites_decoding(const uint8_t *in, size_t ilen, const uint8_t *out, size_t olen) {
    ssize_t ret;
    size_t written;
    uint8_t tmp_buffer[CBOR_BUFFER];
    size_t len;

    len = CBOR_BUFFER;
    written = cbor_suites_decode(tmp_buffer, &len, in, 0, ilen);

    CHECK_TEST_RET_EQ(written, ilen);
    CHECK_TEST_RET_EQ(len, olen);
    CHECK_TEST_RET_EQ(compare_arrays(tmp_buffer, out, olen), (long) 0);

    ret = 0;
    exit:
    return ret;
}

int test_cbor_bstr_id_decoding(const uint8_t *in, size_t ilen, const uint8_t *out, size_t olen) {
    ssize_t ret;
    size_t written;
    size_t len;
}

int main(int argc, char **argv) {
    int ret;
    test_cbor_ctx ctx;

    int tests;

    ssize_t ilen;
    ssize_t olen;

    uint8_t in[CBOR_BUFFER];
    uint8_t out[CBOR_BUFFER];

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--decoding-bytes") == 0) {
            ctx = load_json_cbor_test_file(argv[2]);

            load_from_json_CBOR_TEST_NUM(ctx, &tests);

            for (int i = 0; i < tests; i++) {
                ilen = load_from_json_CBOR_IN(ctx, i + 1, in, CBOR_BUFFER);
                olen = load_from_json_CBOR_OUT(ctx, i + 1, out, CBOR_BUFFER);

                if ((ret = test_cbor_bytes_decoding(in, ilen, out, olen)) != 0) {
                    break;
                }

            }

            close_cbor_test(ctx);
        } else if (strcmp(argv[1], "--encoding-bytes") == 0) {
            ctx = load_json_cbor_test_file(argv[2]);

            load_from_json_CBOR_TEST_NUM(ctx, &tests);

            for (int i = 0; i < tests; i++) {
                ilen = load_from_json_CBOR_IN(ctx, i + 1, in, CBOR_BUFFER);
                olen = load_from_json_CBOR_OUT(ctx, i + 1, out, CBOR_BUFFER);

                if ((ret = test_cbor_bytes_encoding(in, ilen, out, olen)) != 0) {
                    break;
                }

            }

            close_cbor_test(ctx);
        } else if (strcmp(argv[1], "--decoding-suites") == 0) {
            ctx = load_json_cbor_test_file(argv[2]);

            load_from_json_CBOR_TEST_NUM(ctx, &tests);

            for (int i = 0; i < tests; i++) {
                ilen = load_from_json_CBOR_IN(ctx, i + 1, in, CBOR_BUFFER);
                olen = load_from_json_CBOR_OUT(ctx, i + 1, out, CBOR_BUFFER);

                if ((ret = test_cbor_suites_decoding(in, ilen, out, olen)) != 0) {
                    break;
                }

            }
            close_cbor_test(ctx);
        }
    }

    return ret;
}