#include <assert.h>
#include <string.h>

#include <edhoc/cose.h>
#include <edhoc/edhoc.h>
#include <edhoc/cbor_cert.h>

#include "util.h"
#include "json.h"

int test_x5t(cose_algo_t alg, const uint8_t *cert, size_t cert_len, const uint8_t *expected, size_t expected_len) {
    uint8_t out[50];

    cbor_cert_t cbor_cert;

    cbor_cert_load_from_cbor(&cbor_cert, cert, cert_len);

    assert(cose_x5t_attribute(alg, cbor_cert.cert, cbor_cert.cert_len, out, sizeof(out)) == 0);
    assert(compare_arrays(out, expected, expected_len));

    return EDHOC_SUCCESS;
}

int main(int argc, char** argv){
    test_context_ptr ctx;
    uint8_t cert[200], x5t[50];
    ssize_t cert_len, x5t_len;

    if(argc == 3){
        if (strcmp(argv[1], "--x5t") == 0){
            ctx = load_json_test_file(argv[2]);

            cert_len = load_from_json_RESP_CERT(ctx, cert, sizeof(cert));
            assert(cert_len != FAILURE);
            x5t_len = load_from_json_RESP_X5T(ctx, x5t, sizeof(x5t));
            assert(x5t_len != FAILURE);

            assert(test_x5t(COSE_ALGO_SHA256_64, cert, cert_len, x5t, x5t_len) == EDHOC_SUCCESS);

            close_test(ctx);

        }
    }
}