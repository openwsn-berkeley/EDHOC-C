#include <assert.h>
#include <string.h>

#include <edhoc/cose.h>
#include <edhoc/edhoc.h>
#include <edhoc/cbor_cert.h>

#include "util.h"
#include "json.h"

int test_x5t(cose_algo_t alg, const uint8_t *cert, size_t cert_len, const uint8_t *expected, size_t expected_len) {
    ssize_t ret;
    uint8_t out[X5T_BUFFER_SIZE];

    cbor_cert_t cbor_cert;

    cbor_cert_load_from_cbor(&cbor_cert, cert, cert_len);

    CHECK_TEST_RET_GT(cose_x5t_attribute(alg, cbor_cert.cert, cbor_cert.cert_len, out, sizeof(out)), 0);
    CHECK_TEST_RET_EQ(compare_arrays(out, expected, expected_len), (long) 0);


    exit:
    return EDHOC_SUCCESS;
}

int main(int argc, char **argv) {

    /* buffers */
    int ret;
    test_context_ptr ctx;

    uint8_t cred[CRED_SIZE];
    uint8_t cred_id[CRED_ID_SIZE];

    ssize_t cred_len, cred_id_len;

    /* test scenarios */

    ret = 0;

    if (argc == 3) {
        if (strcmp(argv[1], "--x5t") == 0) {
            ctx = load_json_test_file(argv[2]);

            cred_len = load_from_json_RESP_CRED(ctx, cred, sizeof(cred));
            cred_id_len = load_from_json_RESP_CRED_ID(ctx, cred_id, sizeof(cred_id));

            assert(cred_id_len >= 0);
            assert(cred_len >= 0);

            ret = test_x5t(COSE_ALGO_SHA256_64, cred, cred_len, cred_id, cred_id_len);

            close_test(ctx);
        }
    }

    return ret;
}