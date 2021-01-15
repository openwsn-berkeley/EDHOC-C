#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "cbor_internal.h"


int test_cbor_encoding(int value, size_t expected, uint8_t* out, size_t olen){
    uint8_t buf[20];
    size_t written;

    written = cbor_int_encode(value, buf, 0, sizeof(buf));
    assert(written == expected);

    return 0;
}

int main(void){
    uint8_t expected[2] = {0x18, 0x23};
    test_cbor_encoding(35, 2, expected, sizeof(expected));
}