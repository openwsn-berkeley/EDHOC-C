#ifndef EDHOC_TEST_UTIL_H
#define EDHOC_TEST_UTIL_H

#include <stdint.h>
#include <stdlib.h>

#define TEST_FAILED             (-1)
#define TEST_SUCCESSFUL         (0)

#define MESSAGE_1_SIZE          350
#define MESSAGE_2_SIZE          350
#define MESSAGE_3_SIZE          350
#define MESSAGE_4_SIZE          350

#define CERT_SIZE               500
#define CERT_SN_SIZE            20
#define CERT_ISSUER_SIZE        50
#define CERT_SUBJECT_SIZE       50
#define CERT_SUBJECTPK_SIZE     64
#define CERT_SIGNATURE_SIZE     64

#define RPK_SIZE                350
#define X_SIZE                  64
#define D_SIZE                  64

#define DATA_2_SIZE             100
#define DATA_3_SIZE             100

#define TH_SIZE                 64
#define M2_SIZE                 1000
#define SIGNATURE_SIZE          128
#define PAYLOAD_SIZE            500
#define SECRET_SIZE             64
#define INFO_SIZE               100

#define RAW_PUBLIC_KEY          64
#define SYMMETRIC_KEY_SIZE      32
#define IV_SIZE                 32
#define EPHKEY_SIZE             200
#define AUTHKEY_SIZE            200
#define CRED_SIZE               500
#define CRED_ID_SIZE            500
#define CONN_ID_SIZE            4
#define X5T_BUFFER_SIZE         50


#define TEST_CHECK_EQUAL(r1, r2)                                        \
do {                                                                    \
    if ((r1) != (r2)){                                                  \
        fprintf(stderr, "Values are not equal: %ld != %ld\n", r1, r2);  \
        ret = TEST_FAILED;                                              \
        goto exit;                                                      \
    }                                                                   \
} while(0)

#endif /* EDHOC_TEST_UTIL_H */