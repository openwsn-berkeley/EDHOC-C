#include <string.h>

#include "edhoc/edhoc.h"
#include "edhoc/credentials.h"

#include "util.h"
#include "json.h"

int test_cred_identifier_from_cbor(const uint8_t *credId, size_t credIdLen) {
    int ret;

    cred_id_t credIdCtx;

    cred_id_init(&credIdCtx);

    TEST_CHECK_EQUAL((long) cred_id_from_cbor(&credIdCtx, credId, credIdLen), (long) EDHOC_SUCCESS);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_rpk_from_cbor(const uint8_t *rpk,
                       size_t rpk_len,
                       int curve,
                       const uint8_t *x,
                       size_t x_len,
                       const uint8_t *d,
                       size_t d_len) {
    int ret;
    rpk_t rpkCtx;

    cred_rpk_init(&rpkCtx);

    TEST_CHECK_EQUAL((long) cred_rpk_from_cbor(&rpkCtx, rpk, rpk_len), (long) EDHOC_SUCCESS);

    TEST_CHECK_EQUAL((long) rpkCtx.coseKey.crv, (long) curve);

    TEST_CHECK_EQUAL((long) rpkCtx.coseKey.xLen, (long) x_len);
    TEST_CHECK_EQUAL((long) memcmp(rpkCtx.coseKey.x, x, x_len), (long) 0);

    TEST_CHECK_EQUAL((long) rpkCtx.coseKey.dLen, (long) d_len);
    TEST_CHECK_EQUAL((long) memcmp(rpkCtx.coseKey.d, d, d_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}

int test_cert_from_cbor(const uint8_t *raw_cert,
                        size_t cert_len,
                        int cert_type,
                        int subjectPkA,
                        int issuerAlg,
                        const uint8_t *serialNumber,
                        size_t sn_len,
                        const uint8_t *issuer,
                        size_t issuer_len,
                        const uint8_t *subject,
                        size_t subject_len,
                        const uint8_t *subjectPk,
                        size_t subjectPk_len,
                        const uint8_t *signature,
                        size_t signature_len) {
    int ret;
    c509_t certCtx;

    cred_c509_init(&certCtx);

    TEST_CHECK_EQUAL((long) cred_c509_from_cbor(&certCtx, raw_cert, cert_len), (long) EDHOC_SUCCESS);

    TEST_CHECK_EQUAL((long) certCtx.cborCertificateType, (long) cert_type);
    TEST_CHECK_EQUAL((long) certCtx.subjectPublicKeyAlgorithm, (long) subjectPkA);
    TEST_CHECK_EQUAL((long) certCtx.issuerSignatureAlgorithm, (long) issuerAlg);

    TEST_CHECK_EQUAL((long) certCtx.serialNumber.length, sn_len);
    TEST_CHECK_EQUAL((long) memcmp(certCtx.serialNumber.p, serialNumber, sn_len), (long) 0);

    TEST_CHECK_EQUAL((long) certCtx.issuer.length, issuer_len);
    TEST_CHECK_EQUAL((long) memcmp(certCtx.issuer.p, issuer, issuer_len), (long) 0);

    TEST_CHECK_EQUAL((long) certCtx.subject.length, subject_len);
    TEST_CHECK_EQUAL((long) memcmp(certCtx.subject.p, subject, subject_len), (long) 0);

    TEST_CHECK_EQUAL((long) certCtx.subjectPublicKey.length, subjectPk_len);
    TEST_CHECK_EQUAL((long) memcmp(certCtx.subjectPublicKey.p, subjectPk, subjectPk_len), (long) 0);

    TEST_CHECK_EQUAL((long) certCtx.issuerSignatureValue.length, signature_len);
    TEST_CHECK_EQUAL((long) memcmp(certCtx.issuerSignatureValue.p, signature, signature_len), (long) 0);

    ret = TEST_SUCCESSFUL;
    exit:
    return ret;
}


int main(int argc, char **argv) {

    ssize_t ret;
    test_cred_ctx credTestCtx;
    test_edhoc_ctx edhocTestCtx;

    int cert_type, subjectPkA, issuerAlg, curve;

    uint8_t certificate[CERT_SIZE];
    size_t cert_len;

    uint8_t serialNumber[CERT_SN_SIZE];
    size_t sn_len;

    uint8_t issuer[CERT_ISSUER_SIZE];
    size_t issuer_len;

    uint8_t subject[CERT_SUBJECT_SIZE];
    size_t subject_len;

    uint8_t credId[CRED_ID_SIZE];
    size_t credIdLen;

    uint8_t subjectPk[CERT_SUBJECTPK_SIZE];
    size_t subjectPk_len;

    uint8_t signature[CERT_SIGNATURE_SIZE];
    size_t signature_len;

    uint8_t rpk[RPK_SIZE];
    size_t rpk_len;

    uint8_t x[X_SIZE];
    size_t x_len;

    uint8_t d[X_SIZE];
    size_t d_len;

    ret = -1;

    if (argc == 3) {
        if (strcmp(argv[1], "--cert-from-cbor") == 0) {
            credTestCtx = load_json_cred_test_file(argv[2]);

            load_from_json_CBORCERT_TYPE(credTestCtx, &cert_type);
            load_from_json_CBORCERT_SUBJECTPKA(credTestCtx, &subjectPkA);
            load_from_json_CBORCERT_ISSUERALGORITHM(credTestCtx, &issuerAlg);

            cert_len = load_from_json_CBORCERT(credTestCtx, certificate, CERT_SIZE);
            sn_len = load_from_json_CBORCERT_SERIALNUMBER(credTestCtx, serialNumber, CERT_SN_SIZE);
            issuer_len = load_from_json_CBORCERT_ISSUER(credTestCtx, issuer, CERT_ISSUER_SIZE);
            subject_len = load_from_json_CBORCERT_SUBJECT(credTestCtx, subject, CERT_SUBJECT_SIZE);
            subjectPk_len = load_from_json_CBORCERT_SUBJECTPK(credTestCtx, subjectPk, CERT_SUBJECTPK_SIZE);
            signature_len = load_from_json_CBORCERT_SIGNATURE(credTestCtx, signature, CERT_SIGNATURE_SIZE);

            ret = test_cert_from_cbor(certificate,
                                      cert_len,
                                      cert_type,
                                      subjectPkA,
                                      issuerAlg,
                                      serialNumber,
                                      sn_len,
                                      issuer,
                                      issuer_len,
                                      subject,
                                      subject_len,
                                      subjectPk,
                                      subjectPk_len,
                                      signature,
                                      signature_len);

            close_cred_test(credTestCtx);

        } else if (strcmp(argv[1], "--rpk-from-cbor") == 0) {
            credTestCtx = load_json_cred_test_file(argv[2]);

            rpk_len = load_from_json_RPK(credTestCtx, rpk, RPK_SIZE);
            x_len = load_from_json_RPK_X(credTestCtx, x, X_SIZE);
            d_len = load_from_json_RPK_D(credTestCtx, d, D_SIZE);

            load_from_json_RPK_CURVE(credTestCtx, &curve);

            ret = test_rpk_from_cbor(rpk, rpk_len, curve, x, x_len, d, d_len);

            close_cred_test(credTestCtx);

        } else if (strcmp(argv[1], "--cred-id-from-cbor") == 0) {
            edhocTestCtx = load_json_edhoc_test_file(argv[2]);

            credIdLen = load_from_json_INIT_CRED_ID(edhocTestCtx, credId, CRED_ID_SIZE);

            ret = test_cred_identifier_from_cbor(credId, credIdLen);

            close_edhoc_test(edhocTestCtx);
        }
    }

    return ret;
}