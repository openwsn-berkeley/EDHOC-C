#ifndef EDHOC_TEST_UTIL_H
#define EDHOC_TEST_UTIL_H

#include <stdint.h>

#define MESSAGE_1_SIZE          350
#define MESSAGE_2_SIZE          350
#define MESSAGE_3_SIZE          350

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

#define CHECK_TEST_RET_GT(f, v)                                     \
do{                                                                 \
    if((ret = (f)) <= (v)){                                         \
        fprintf(stderr, "Test returned: %ld\n", ret);               \
        goto exit;                                                  \
    }                                                               \
} while(0)

#define CHECK_TEST_RET_EQ(f, v)                                         \
do{                                                                     \
    if((ret = (f)) != (v)){                                             \
        if (ret < 0){                                                   \
            fprintf(stderr, "Test returned: %ld\n", ret);               \
        } else {                                                        \
            fprintf(stderr, "Expected %ld, but got %ld\n", v, ret);     \
        }                                                               \
        goto exit;                                                      \
    }                                                                   \
} while(0)

int compare_arrays(const uint8_t a[], const uint8_t b[], int size);

#endif /* EDHOC_TEST_UTIL_H */