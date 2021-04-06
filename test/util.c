#include <stdio.h>
#include <string.h>

#include "util.h"


const uint8_t v1InitCredId[] = {112, 93, 88, 69, 243, 111, 198, 166};
const uint8_t v1InitCred[] = {88, 101, 84, 19, 32, 76, 62, 188, 52, 40, 166, 207, 87, 226, 76, 157, 239, 89, 101, 23,
                              112, 68, 155, 206, 126, 198, 86, 30, 82, 67, 58, 165, 94, 113, 241, 250, 52, 178, 42, 156,
                              164, 161, 225, 41, 36, 234, 225, 209, 118, 96, 136, 9, 132, 73, 203, 132, 143, 252, 121,
                              95, 136, 175, 196, 156, 190, 138, 253, 209, 186, 0, 159, 33, 103, 94, 143, 108, 119, 164,
                              162, 195, 1, 149, 96, 31, 111, 10, 8, 82, 151, 139, 212, 61, 40, 32, 125, 68, 72, 101, 2,
                              255, 123, 221, 166};

const uint8_t v1RespCredId[] = {104, 68, 7, 138, 83, 243, 18, 245};
const uint8_t v1RespCred[] = {88, 100, 199, 136, 55, 0, 22, 184, 150, 91, 219, 32, 116, 191, 248, 46, 90, 32, 224, 155,
                              236, 33, 248, 64, 110, 134, 68, 43, 135, 236, 63, 242, 69, 183, 10, 71, 98, 77, 201, 205,
                              198, 130, 75, 42, 76, 82, 233, 94, 201, 214, 176, 83, 75, 113, 194, 180, 158, 75, 249, 3,
                              21, 0, 206, 230, 134, 153, 121, 194, 151, 187, 90, 139, 56, 30, 152, 219, 113, 65, 8, 65,
                              94, 92, 80, 219, 120, 151, 76, 39, 21, 121, 176, 22, 51, 163, 239, 98, 113, 190, 92, 34,
                              94, 178};


const uint8_t v2InitCredId[] = {35};
const uint8_t v2InitCred[] = {164, 1, 1, 32, 4, 33, 88, 32, 44, 68, 12, 193, 33, 248, 215, 242, 76, 59, 14, 65, 174,
                              218, 254, 156, 170, 79, 78, 122, 187, 131, 94, 195, 15, 29, 232, 138, 219, 150, 255, 113,
                              108, 115, 117, 98, 106, 101, 99, 116, 32, 110, 97, 109, 101, 96};

const uint8_t v2RespCredId[] = {5};
const uint8_t v2RespCred[] = {164, 1, 1, 32, 4, 33, 88, 32, 163, 255, 38, 53, 149, 190, 179, 119, 209, 160, 206, 29, 4,
                              218, 210, 212, 9, 102, 172, 107, 203, 98, 32, 81, 184, 70, 89, 24, 77, 93, 154, 50, 108,
                              115, 117, 98, 106, 101, 99, 116, 32, 110, 97, 109, 101, 96};

const uint8_t v3InitCredId[] = {214, 254, 190, 38, 110, 7, 78, 99};
const uint8_t v3InitCred[] = {88, 112, 249, 158, 145, 62, 27, 141, 10, 72, 222, 221, 142, 157, 122, 119, 183, 129, 243,
                              224, 67, 200, 154, 176, 186, 235, 216, 70, 81, 91, 39, 186, 15, 21, 97, 19, 46, 119, 61,
                              186, 196, 82, 22, 47, 163, 64, 239, 251, 125, 56, 181, 230, 76, 95, 195, 105, 240, 33,
                              172, 102, 26, 129, 52, 23, 106, 173, 159, 69, 212, 214, 47, 186, 72, 62, 232, 248, 146,
                              147, 150, 43, 127, 123, 17, 93, 65, 112, 192, 233, 20, 206, 92, 50, 34, 42, 246, 148, 164,
                              230, 60, 155, 75, 2, 248, 115, 222, 53, 217, 160, 36, 61, 118, 239, 4, 115};

const uint8_t v3RespCredId[] = {32};
const uint8_t v3RespCred[] = {164, 1, 1, 32, 4, 33, 88, 32, 41, 149, 23, 25, 82, 46, 244, 50, 1, 190, 19, 62, 72, 143,
                              233, 33, 216, 187, 91, 79, 20, 238, 160, 185, 123, 206, 96, 89, 52, 190, 21, 98, 108,
                              115, 117, 98, 106, 101, 99, 116, 32, 110, 97, 109, 101, 96};

const uint8_t v4InitCredId[] = {32};
const uint8_t v4InitCred[] = {164, 1, 1, 32, 4, 33, 88, 32, 164, 5, 192, 206, 97, 90, 205, 38, 96, 112, 148, 194, 75,
                              90, 131, 122, 187, 176, 241, 44, 167, 141, 92, 207, 162, 109, 136, 78, 28, 34, 75, 84,
                              108, 115, 117, 98, 106, 101, 99, 116, 32, 110, 97, 109, 101, 96};

const uint8_t v4RespCredId[] = {244, 156, 200, 116, 110, 76, 202, 96};
const uint8_t v4RespCred[] = {88, 117, 192, 3, 102, 37, 227, 168, 136, 206, 254, 90, 177, 218, 130, 16, 8, 165, 239,
                              153, 53, 8, 75, 59, 115, 32, 205, 155, 230, 81, 217, 220, 48, 138, 49, 11, 63, 202, 105,
                              187, 104, 227, 155, 236, 186, 126, 93, 50, 140, 95, 240, 19, 89, 234, 186, 176, 206, 230,
                              246, 168, 32, 130, 171, 57, 163, 149, 218, 168, 153, 42, 252, 227, 71, 60, 172, 102, 79,
                              190, 160, 91, 57, 223, 221, 5, 83, 139, 43, 94, 187, 53, 199, 255, 186, 212, 89, 65, 83,
                              43, 37, 162, 28, 78, 133, 106, 77, 98, 151, 142, 23, 164, 51, 212, 55, 173, 32, 56, 202,
                              244, 135};

cred_map_t credentialStore[] = {
        {
                v1InitCredId,
                sizeof(v1InitCredId),
                v1InitCred,
                sizeof(v1InitCred),
        },
        {
                v1RespCredId,
                sizeof(v1RespCredId),
                v1RespCred,
                sizeof(v1RespCred)
        },
        {
                v2InitCredId,
                sizeof(v2InitCredId),
                v2InitCred,
                sizeof(v2InitCred),
        },
        {
                v2RespCredId,
                sizeof(v2RespCredId),
                v2RespCred,
                sizeof(v2RespCred)
        },
        {
                v3InitCredId,
                sizeof(v3InitCredId),
                v3InitCred,
                sizeof(v3InitCred)
        },
        {
                v3RespCredId,
                sizeof(v3RespCredId),
                v3RespCred,
                sizeof(v3RespCred)
        },
        {
                v4InitCredId,
                sizeof(v4InitCredId),
                v4InitCred,
                sizeof(v4InitCred)
        },
        {
                v4RespCredId,
                sizeof(v4RespCredId),
                v4RespCred,
                sizeof(v4RespCred)
        },
};

ssize_t compare_arrays(const uint8_t a[], const uint8_t b[], int size) {
    for (int i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "Arrays are not equal at index: %d\n", i);
            return -1;
        }
    }
    return 0;
}

int f_remote_creds(const uint8_t *key, size_t keyLen, const uint8_t **out, size_t *olen) {
    int ret, i;

    for (i = 0; i < sizeof(credentialStore) / sizeof(cred_map_t); i++) {
        if (credentialStore[i].keyLen == keyLen && memcmp(credentialStore[i].key, key, keyLen) == 0) {
            *out = credentialStore[i].value;
            *olen = credentialStore[i].valueLen;
            break;
        }
    }

    if (i == sizeof(credentialStore) / sizeof(cred_map_t)) {
        out = NULL;
        *olen = 0;
        ret = (-0x11);
    } else {
        ret = 0;
    }

    return ret;
}
